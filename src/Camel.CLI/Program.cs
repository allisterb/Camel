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

        // Write the per-case audit log into the case's logs/ directory (alongside the chat transcript and
        // token-usage summary the SessionEnd hook writes there) when create-case baked a --case-dir into
        // the .mcp.json, so the whole audit trail is bundled in one place. Falls back to <assembly-dir>/logs
        // for a manually-launched server with no case dir. The file is named audit-<caseId>.clef.
        var logDir = string.IsNullOrWhiteSpace(opts.CaseDir)
            ? Path.Combine(AssemblyLocation, "logs")
            : Path.Combine(opts.CaseDir, "logs");
        Runtime.WithAuditLog(logDir);

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
        foreach (var sub in new[] { "logs", "exports", "reports" })
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

        // reports/report.html + reports/report.js — a static, dependency-free HTML app for a human reviewer to
        // browse the findings and trace each one to the exact audit-log entries (executions + commands) that prove
        // it, and to filter the whole audit trail (criterion 6). It sits in reports/ alongside report.md; the .html
        // carries the case id (so it can auto-load ../logs/audit-<caseId>.clef when served, falling back to a file
        // picker), the .js is static. A generated reports/audit-data.js embeds the log for offline double-click.
        var reportsDir = Path.Combine(caseDir, "reports");
        var viewerHtmlPath = Path.Combine(reportsDir, "report.html");
        if (File.Exists(viewerHtmlPath))
        {
            Info($"{viewerHtmlPath} already exists — leaving it untouched.");
        }
        else
        {
            File.WriteAllText(viewerHtmlPath,
                ReadEmbedded("Camel.CLI.CaseTemplate.report.html")
                    .Replace("__CASE_ID__", opts.CaseId)
                    .Replace("__ACCURACY_B64__", "")     // no accuracy.md yet; Accuracy tab shows a placeholder
                    .Replace("__IOCS_B64__", ""));       // no iocs.csv yet; IOCs tab shows a placeholder
            File.WriteAllText(Path.Combine(reportsDir, "report.js"),
                ReadEmbedded("Camel.CLI.CaseTemplate.report.js"));
            Info($"Wrote {viewerHtmlPath} (+ report.js)");
        }

        Info($"Case '{opts.CaseId}' ready at {caseDir}.");
        AnsiConsole.MarkupLine($"[cyan]\nFill in the case details in {Path.Combine(caseDir, "CLAUDE.md")}. When you are ready launch Claude in that directory.[/]");
        AnsiConsole.MarkupLine($"[grey]Open {viewerHtmlPath} in a browser to review findings and the audit trail.[/]");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Claude Code <c>SessionEnd</c> hook (wired into each case's <c>.claude/settings.json</c> by
    /// <c>create-case</c>). Reads the hook JSON payload from stdin, then (1) copies the client chat
    /// transcript (<c>transcript_path</c>) into the case at <c>logs/chatlog-*.jsonl</c>, and (2) writes a
    /// client-side token-consumption summary to <c>logs/token-usage.json</c> (summed from the transcript's
    /// per-turn <c>usage</c> records) — both bundled in <c>logs/</c> next to the audit log for the judges'
    /// efficiency/cost review. Anchored to <c>$CLAUDE_PROJECT_DIR</c> (the case root Claude Code exports to
    /// hooks), falling back to the cwd. Best-effort: never fail the session.
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
            var logsDir = Path.Combine(baseDir, "logs");
            Directory.CreateDirectory(logsDir);

            var sessionId = payload?["session_id"]?.GetValue<string>() ?? "session";
            var ts = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
            var dst = Path.Combine(logsDir, $"chatlog-{sessionId}-{ts}.jsonl");
            File.Copy(src, dst, overwrite: true);
            Console.Out.WriteLine($"[preserve-chatlog] Preserved client chat log -> {dst}");

            WriteTokenUsage(src, logsDir, sessionId);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[preserve-chatlog] Failed to preserve chat log: {ex.Message}");
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Sums the client-side token consumption from a Claude Code transcript (each <c>assistant</c> line
    /// carries a <c>message.usage</c> record) and writes <c>analysis/token-usage.json</c>: grand totals
    /// (input / output / cache-create / cache-read / sum) plus a per-model breakdown and the turn count.
    /// Best-effort and isolated so a parsing hiccup never breaks chat-log preservation.
    /// </summary>
    static void WriteTokenUsage(string transcriptPath, string logsDir, string sessionId)
    {
        try
        {
            long input = 0, output = 0, cacheCreate = 0, cacheRead = 0;
            int turns = 0;
            // model -> [turns, input, output, cacheCreate, cacheRead]
            var byModel = new Dictionary<string, long[]>(StringComparer.Ordinal);

            foreach (var line in File.ReadLines(transcriptPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                JsonNode? n;
                try { n = JsonNode.Parse(line); } catch { continue; }
                if (n?["type"]?.GetValue<string>() != "assistant") continue;
                var msg = n["message"];
                var usage = msg?["usage"];
                if (usage is null) continue;

                long Get(string k) => usage[k]?.GetValue<long>() ?? 0;
                long i = Get("input_tokens"), o = Get("output_tokens"),
                     cc = Get("cache_creation_input_tokens"), cr = Get("cache_read_input_tokens");
                var model = msg?["model"]?.GetValue<string>() ?? "unknown";

                input += i; output += o; cacheCreate += cc; cacheRead += cr; turns++;
                if (!byModel.TryGetValue(model, out var m)) { m = new long[5]; byModel[model] = m; }
                m[0]++; m[1] += i; m[2] += o; m[3] += cc; m[4] += cr;
            }

            long total = input + output + cacheCreate + cacheRead;
            long totalInput = input + cacheCreate + cacheRead;
            // Cached (reused from the prompt cache, billed at the reduced cache-read rate) vs new (fresh
            // tokens billed at standard/cache-write/output rates). cache_creation is a one-time write of
            // new input into the cache, so it counts as new, not cached.
            long cachedTokens = cacheRead;
            long newTokens = input + cacheCreate + output;
            var summary = new JsonObject
            {
                ["sessionId"] = sessionId,
                ["generatedUtc"] = DateTime.UtcNow.ToString("o"),
                ["transcript"] = transcriptPath,
                ["assistantTurns"] = turns,
                ["totals"] = new JsonObject
                {
                    ["input_tokens"] = input,
                    ["output_tokens"] = output,
                    ["cache_creation_input_tokens"] = cacheCreate,
                    ["cache_read_input_tokens"] = cacheRead,
                    ["total_tokens"] = total,
                },
                ["breakdown"] = new JsonObject
                {
                    ["cached_tokens"] = cachedTokens,                       // cache_read — reused, billed ~0.1x
                    ["new_tokens"] = newTokens,                            // input + cache_creation + output
                    ["new_input_tokens"] = input + cacheCreate,           // fresh input (full + cache-write premium)
                    ["output_tokens"] = output,
                    ["cache_read_fraction_of_input"] = totalInput > 0
                        ? Math.Round((double)cacheRead / totalInput, 4)
                        : 0.0,
                },
                ["byModel"] = new JsonObject(byModel.Select(kv =>
                    new KeyValuePair<string, JsonNode?>(kv.Key, new JsonObject
                    {
                        ["turns"] = kv.Value[0],
                        ["input_tokens"] = kv.Value[1],
                        ["output_tokens"] = kv.Value[2],
                        ["cache_creation_input_tokens"] = kv.Value[3],
                        ["cache_read_input_tokens"] = kv.Value[4],
                    }))),
            };

            Directory.CreateDirectory(logsDir);
            var path = Path.Combine(logsDir, "token-usage.json");
            File.WriteAllText(path, summary.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Console.Out.WriteLine($"[preserve-chatlog] Token usage -> {path} (total {total:N0} tokens over {turns} turns)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[preserve-chatlog] Token-usage summary failed: {ex.Message}");
        }
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
