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
        // The preserve-chatlog verb runs as a Claude Code SessionEnd hook: keep stdout clean (no logo) so
        // the hook's output isn't polluted, and don't tee logging to the console.
        bool isHook = args.Contains("preserve-chatlog");
        if (!isHook) PrintLogo();
        Runtime.WithFileAndConsoleLogging("Camel", "CLI", args.Contains("--debug"));
        var parser = new Parser(with =>
        {
            with.CaseInsensitiveEnumValues = true;
            with.HelpWriter = null;
        });
        var result = parser.ParseArguments<ServerOptions, CreateCaseOptions, PreserveChatlogOptions>(args);
        try
        {
            await result.MapResult(

                async (ServerOptions opts) => await HandleServerArgs(opts),
                async (CreateCaseOptions opts) => await HandleCreateCaseArgs(opts),
                async (PreserveChatlogOptions opts) => await HandlePreserveChatlog(opts),
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

        // Write the per-case audit log into the case directory (as <case-dir>/audit/) when create-case
        // baked a --case-dir into the .mcp.json, so the audit trail is bundled with the self-contained
        // case. Falls back to <assembly-dir>/audit for a manually-launched server with no case dir.
        var auditDir = string.IsNullOrWhiteSpace(opts.CaseDir)
            ? Path.Combine(AssemblyLocation, "audit")
            : Path.Combine(opts.CaseDir, "audit");
        Runtime.WithAuditLog(auditDir);

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

        // .claude/settings.json — project-scoped code-mode policy (deny Bash, allow only the Camel MCP
        // tools + scoped file writes) plus the SessionEnd hook that preserves the client chat log into the
        // case. The hook runs THIS CLI's `preserve-chatlog` verb (`dotnet "<dll>" preserve-chatlog`) so it
        // needs only the .NET runtime the case already requires — no python/node. Emitting per case keeps
        // the case self-contained (nothing in ~/.claude). Existing file left untouched.
        var dotClaude = Path.Combine(caseDir, ".claude");
        Directory.CreateDirectory(dotClaude);

        var settingsPath = Path.Combine(dotClaude, "settings.json");
        if (File.Exists(settingsPath))
        {
            Info($"{settingsPath} already exists — leaving it untouched.");
        }
        else
        {
            var node = JsonNode.Parse(ReadEmbedded("Camel.CLI.CaseTemplate.settings.json"))!;
            node["hooks"]!["SessionEnd"]![0]!["hooks"]![0]!["command"] =
                $"dotnet \"{CliDllPath()}\" preserve-chatlog";
            File.WriteAllText(settingsPath, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Info($"Wrote {settingsPath}");
        }

        Info($"Case '{opts.CaseId}' ready at {caseDir}.");
        AnsiConsole.MarkupLine($"[cyan]\nFill in the case details in {Path.Combine(caseDir, "CLAUDE.md")}. When you are ready launch Claude in that directory.[/]");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Claude Code <c>SessionEnd</c> hook (wired into each case's <c>.claude/settings.json</c> by
    /// <c>create-case</c>). Reads the hook JSON payload from stdin, then copies the client chat transcript
    /// (<c>transcript_path</c>) into the case at <c>analysis/chatlogs/</c> so the chat log is bundled with
    /// the audit trail. Anchored to <c>$CLAUDE_PROJECT_DIR</c> (the case root Claude Code exports to hooks),
    /// falling back to the cwd. Best-effort: never fail the session — return 0 even on a missing transcript.
    /// </summary>
    static Task HandlePreserveChatlog(PreserveChatlogOptions opts)
    {
        try
        {
            var stdin = Console.In.ReadToEnd();
            // Tolerate a leading UTF-8 BOM / surrounding whitespace on the piped payload (varies by host).
            stdin = stdin.Trim().TrimStart('﻿');
            if (string.IsNullOrWhiteSpace(stdin)) return Task.CompletedTask;

            var payload = JsonNode.Parse(stdin);
            var src = payload?["transcript_path"]?.GetValue<string>();
            if (string.IsNullOrEmpty(src) || !File.Exists(src))
            {
                Console.Error.WriteLine($"[preserve-chatlog] transcript_path missing or not found: {src}");
                return Task.CompletedTask;
            }

            var baseDir = Environment.GetEnvironmentVariable("CLAUDE_PROJECT_DIR");
            if (string.IsNullOrWhiteSpace(baseDir)) baseDir = Directory.GetCurrentDirectory();
            var dstDir = Path.Combine(baseDir, "analysis", "chatlogs");
            Directory.CreateDirectory(dstDir);

            var sessionId = payload?["session_id"]?.GetValue<string>() ?? "session";
            var ts = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
            var dst = Path.Combine(dstDir, $"chatlog-{sessionId}-{ts}.jsonl");
            File.Copy(src, dst, overwrite: true);
            Console.Out.WriteLine($"[preserve-chatlog] Preserved client chat log -> {dst}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[preserve-chatlog] Failed to preserve chat log: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    /// <summary>Path to this running CLI assembly (empty for single-file publishes — fall back to the assembly dir).</summary>
    static string CliDllPath()
    {
        var dll = Assembly.GetEntryAssembly()?.Location;
        return string.IsNullOrEmpty(dll) ? Path.Combine(AssemblyLocation, "Camel.CLI.dll") : dll;
    }

    /// <summary>
    /// Builds the args array for the generated <c>.mcp.json</c>: launches this CLI assembly's <c>server</c>
    /// verb, carrying through the connection flags passed to <c>create-case</c> (any of --host/--user/--pass/
    /// --port implies --ssh unless --local was given), so Claude Code starts Camel in the requested mode.
    /// </summary>
    static List<string> BuildServerArgs(CreateCaseOptions opts)
    {
        var args = new List<string> { CliDllPath(), "server" };
        bool conn = !string.IsNullOrWhiteSpace(opts.Host) || !string.IsNullOrWhiteSpace(opts.User)
                    || !string.IsNullOrWhiteSpace(opts.Password) || opts.Port.HasValue;
        if (opts.Local) args.Add("--local");
        else if (opts.Ssh || conn) args.Add("--ssh");
        if (!string.IsNullOrWhiteSpace(opts.Host)) { args.Add("--host"); args.Add(opts.Host); }
        if (!string.IsNullOrWhiteSpace(opts.User)) { args.Add("--user"); args.Add(opts.User); }
        if (!string.IsNullOrWhiteSpace(opts.Password)) { args.Add("--pass"); args.Add(opts.Password); }
        if (opts.Port.HasValue) { args.Add("--port"); args.Add(opts.Port.Value.ToString()); }
        // Bake the absolute case dir so the server writes its audit log into the case (not next to the dll).
        args.Add("--case-dir");
        args.Add(Path.GetFullPath(Path.Combine(opts.CaseDir, opts.CaseId)));
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
    static string host = "";
}
