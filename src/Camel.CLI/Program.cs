namespace Camel.CLI;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
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
        var result = parser.ParseArguments<ServerOptions, DfirServerOptions, PenTestServerOptions, CreateCaseOptions, PreserveChatlogOptions, BakeReportOptions>(args);
        try
        {
            await result.MapResult(

                // The PenTest and DFIR verbs subclass ServerOptions; MapResult dispatches on the concrete parsed
                // type, so the more-derived handlers must precede the ServerOptions ('server' alias = DFIR) one.
                async (PenTestServerOptions opts) => await HandleServerArgs(opts, InvestigationType.PenTest),
                async (DfirServerOptions opts) => await HandleServerArgs(opts, InvestigationType.DFIR),
                async (ServerOptions opts) => await HandleServerArgs(opts, InvestigationType.DFIR),
                async (CreateCaseOptions opts) => await HandleCreateCaseArgs(opts),
                async (PreserveChatlogOptions opts) => await HandlePreserveChatlog(opts),
                async (BakeReportOptions opts) => await HandleBakeReportArgs(opts),
                errs => HandleParseError(result, errs)
            );
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
        }
    }

    static async Task HandleServerArgs(ServerOptions opts, InvestigationType investigation)
    {
        if (config is null) throw new Exception("Configuration not loaded.");

        // Write the per-case audit log into the case's logs/ directory (alongside the chat transcript and
        // token-usage summary the SessionEnd hook writes there) when create-case baked a --case-dir into
        // the .mcp.json, so the whole audit trail is bundled in one place. Falls back to <assembly-dir>/logs
        // for a manually-launched server with no case dir. The file is named audit-<caseId>.clef.
        var caseRoot = string.IsNullOrWhiteSpace(opts.CaseDir) ? AssemblyLocation : opts.CaseDir;
        var logDir = Path.Combine(caseRoot, "logs");
        Runtime.WithAuditLog(logDir);

        // Retain raw knowledge-base responses (content-addressed) under the case's exports/, so any external-intel
        // finding can be verified byte-for-byte. The KB client reads this config key; unset = retention off.
        config["KnowledgeBaseRetentionDir"] = Path.Combine(caseRoot, "exports", "kb");

        // The case directory itself, so the PenTest SetEngagement tool can resolve a supplied authorization
        // document (relative to the case dir) and preserve a hashed copy under reports/authorization/. Case-side,
        // local to where the CLI/server runs (the case dir holds logs/exports/reports regardless of SSH platform).
        config["CaseDir"] = caseRoot;

        // Resolve the active platform profile (the config section holding this box's connection details + tool
        // paths): explicit --platform wins, else the config 'Platform' key, else the investigation default
        // (DFIR→SIFT, PenTest→Kali). Connection overrides below target THIS profile, so --host/--user/... point
        // the chosen platform at a remote box without editing appsettings.json. AuditEnvironment.CreateFromConfig
        // and the toolkits both read {platform}:..., so setting Platform here is what selects the box end-to-end.
        var platform = !string.IsNullOrWhiteSpace(opts.Platform) ? opts.Platform
                     : !string.IsNullOrWhiteSpace(config["Platform"]) ? config["Platform"]!
                     : (investigation == InvestigationType.PenTest ? "Kali" : "SIFT");
        config["Platform"] = platform;

        if (opts.Ssh)
        {
            config[$"{platform}:Environment"] = "Ssh";
        }
        else if (opts.Local)
        {
            config[$"{platform}:Environment"] = "Local";
        }

        // SSH connection overrides from the command line, so the user can point Camel at a remote box without
        // editing appsettings.json (e.g. running against a remote SIFT or Kali host). Any supplied detail implies
        // SSH mode unless the user explicitly forced --local.
        if (!string.IsNullOrWhiteSpace(opts.Host)) config[$"{platform}:Host"] = opts.Host;
        if (!string.IsNullOrWhiteSpace(opts.User)) config[$"{platform}:User"] = opts.User;
        if (!string.IsNullOrWhiteSpace(opts.Password)) config[$"{platform}:Password"] = opts.Password;
        if (opts.Port.HasValue) config[$"{platform}:Port"] = opts.Port.Value.ToString();
        if (!opts.Local && (!string.IsNullOrWhiteSpace(opts.Host) || !string.IsNullOrWhiteSpace(opts.User)
                            || !string.IsNullOrWhiteSpace(opts.Password) || opts.Port.HasValue))
        {
            config[$"{platform}:Environment"] = "Ssh";
        }
        // Default the SSH port when connection details were supplied on the command line but no port was set
        // anywhere, so SSH mode doesn't fail on a missing {platform}:Port.
        if (Enum.Parse<EnvironmentType>(GetRequiredValue(config, $"{platform}:Environment")) == EnvironmentType.Ssh
            && string.IsNullOrWhiteSpace(config[$"{platform}:Port"]))
        {
            config[$"{platform}:Port"] = "22";
        }

        if (Enum.Parse<EnvironmentType>(GetRequiredValue(config, $"{platform}:Environment")) == EnvironmentType.Ssh)
        {
            // Fail fast: verify SSH connectivity once at startup (sessions then connect lazily on first use).
            host = GetRequiredValue(config, $"{platform}:Host");
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

        var mode = investigation == InvestigationType.PenTest ? "PenTest (red-team)" : "DFIR (blue-team)";
        if (opts.Http)
        {
            Info("Starting Camel {Mode} MCP Server in HTTP mode on platform '{Platform}'.", mode, platform);
            await CamelMCPServer.RunHttpAsync(config, investigation);
        }
        else
        {
            Info("Starting Camel {Mode} MCP Server in stdio mode on platform '{Platform}'.", mode, platform);
            await CamelMCPServer.RunStdioAsync(config, investigation);
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
            // Pick the brief for the investigation type: the DFIR (blue) analyst brief or the PenTest (red)
            // operator brief. Both are embedded templates with __CASE_ID__ substituted.
            var template = opts.Type == InvestigationType.PenTest
                ? "Camel.CLI.CaseTemplate.CLAUDE.pentest.md"
                : "Camel.CLI.CaseTemplate.CLAUDE.md";
            var claude = ReadEmbedded(template).Replace("__CASE_ID__", opts.CaseId);
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
        // tools + scoped file writes) plus the Stop and SessionEnd hooks that preserve the client chat log
        // into the case and bake the report. Stop fires after every agent turn (so the report stays current
        // throughout the session), SessionEnd is the final pass on clean exit. Both run THIS CLI's
        // `preserve-chatlog` verb (`dotnet "<dll>" preserve-chatlog`) so they need only the .NET runtime the
        // case already requires — no python/node. Emitting per case keeps the case self-contained (nothing in
        // ~/.claude). Existing file left untouched.
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
            var hookCmd = $"dotnet \"{CliDllPath()}\" preserve-chatlog";
            node["hooks"]!["Stop"]![0]!["hooks"]![0]!["command"] = hookCmd;
            node["hooks"]!["SessionEnd"]![0]!["hooks"]![0]!["command"] = hookCmd;
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
        AnsiConsole.MarkupLine($"[cyan]When the investigation completes, open {viewerHtmlPath} in a browser to review findings and the audit trail.[/]");
        return Task.CompletedTask;
    }

    static Task HandleBakeReportArgs(BakeReportOptions opts)
    {
        var caseDir = Path.GetFullPath(opts.CaseDir);
        if (!Directory.Exists(caseDir))
        {
            Error($"Case directory not found: {caseDir}");
            Environment.Exit(2);
        }
        var n = BakeReport(caseDir);
        Info($"Baked report for {caseDir} ({n} data file(s) embedded).");
        AnsiConsole.MarkupLine($"[grey]Open {Path.Combine(caseDir, "reports", "report.html")} in a browser.[/]");
        return Task.CompletedTask;
    }

    // JSON serialization for the generated *.js data files: relaxed escaping (these are standalone .js, not inline
    // HTML, so no need to escape < > & — keeps the embed smaller and readable).
    static readonly JsonSerializerOptions JsDataOpts = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>
    /// Regenerates a case's self-contained report viewer and embeds its current data so <c>reports/report.html</c>
    /// opens by double-click with no server: re-emits <c>report.html</c> (case id + base64 <c>accuracy.md</c> /
    /// <c>iocs.csv</c>) and <c>report.js</c> from the embedded template, and writes the sibling <c>audit-data.js</c>
    /// (the <c>.clef</c>) and <c>chatlog-data.js</c> (trimmed conversation). Best-effort and idempotent; missing
    /// inputs are simply skipped. Returns the number of sibling data files written.
    /// </summary>
    static int BakeReport(string caseDir)
    {
        var reportsDir = Path.Combine(caseDir, "reports");
        var logsDir = Path.Combine(caseDir, "logs");
        Directory.CreateDirectory(reportsDir);
        var caseId = ResolveCaseId(caseDir, logsDir);

        static string B64OfFile(string p) =>
            File.Exists(p) ? Convert.ToBase64String(Encoding.UTF8.GetBytes(File.ReadAllText(p))) : "";

        // report.html + report.js — regenerated from the embedded template (they are viewer files, not user-edited),
        // so re-baking also upgrades an older case's viewer to the current template.
        File.WriteAllText(Path.Combine(reportsDir, "report.html"),
            ReadEmbedded("Camel.CLI.CaseTemplate.report.html")
                .Replace("__CASE_ID__", caseId)
                .Replace("__ACCURACY_B64__", B64OfFile(Path.Combine(reportsDir, "accuracy.md")))
                .Replace("__IOCS_B64__", B64OfFile(Path.Combine(reportsDir, "iocs.csv"))));
        File.WriteAllText(Path.Combine(reportsDir, "report.js"), ReadEmbedded("Camel.CLI.CaseTemplate.report.js"));

        var dataFiles = 0;

        // The data sidecars are written independently and best-effort: a per-turn Stop bake runs WHILE the case's
        // MCP server is still appending to the CLEF, so the reads use a shared open (ReadAllTextShared) and a single
        // sidecar failing must NOT abort the others (it previously did — the audit read threw a sharing violation,
        // leaving report.html/js written but every data sidecar missing).
        var clef = Path.Combine(logsDir, $"audit-{caseId}.clef");
        if (!File.Exists(clef) && Directory.Exists(logsDir))
            clef = Directory.EnumerateFiles(logsDir, "audit-*.clef").FirstOrDefault() ?? clef;

        // audit-data.js — embed the per-case CLEF (read with a shared lock since the live server still writes it).
        if (File.Exists(clef))
            dataFiles += TryWriteSidecar("audit-data.js", () =>
            {
                var name = Path.GetFileName(clef);
                File.WriteAllText(Path.Combine(reportsDir, "audit-data.js"),
                    $"/* Embedded copy of logs/{name} so report.html opens with data by double-click. */\n" +
                    $"window.__AUDIT_CLEF__={JsonSerializer.Serialize(ReadAllTextShared(clef), JsDataOpts)};\n" +
                    $"window.__AUDIT_SOURCE__={JsonSerializer.Serialize($"../logs/{name} (embedded)", JsDataOpts)};\n");
            });

        // chatlog-data.js — trimmed reconstruction of the preserved client transcript(s).
        dataFiles += TryWriteSidecar("chatlog-data.js", () =>
        {
            if (BuildChatlogData(logsDir) is not string chat) return false;
            File.WriteAllText(Path.Combine(reportsDir, "chatlog-data.js"),
                "/* Trimmed reconstruction of logs/chatlog-*.jsonl for the Conversation tab. */\n" +
                $"window.__CHATLOG__={chat};\n");
            return true;
        });

        // token-usage-data.js — token economics + runtime breakdown, aggregated across the same per-session
        // transcripts the conversation is built from. toolCallMs (from the CLEF) splits run time into tool vs model.
        dataFiles += TryWriteSidecar("token-usage-data.js", () =>
        {
            if (BuildTokenUsageData(logsDir) is not JsonObject tokens) return false;
            if (File.Exists(clef)) tokens["toolCallMs"] = SumToolCallMs(clef);
            File.WriteAllText(Path.Combine(reportsDir, "token-usage-data.js"),
                "/* Token-usage + runtime summary for the Conversation tab, aggregated from logs/chatlog-*.jsonl and the audit CLEF. */\n" +
                $"window.__TOKEN_USAGE__={tokens.ToJsonString(JsDataOpts)};\n");
            return true;
        });

        // engagement-data.js — the structured engagement authorization for a pen-test case's Authorization & Scope
        // tab. SetEngagement serializes it to reports/authorization/engagement.json; a DFIR case has none, so the
        // sidecar is simply skipped. The JSON is embedded directly as the JS object (JSON is valid JS-literal syntax).
        dataFiles += TryWriteSidecar("engagement-data.js", () =>
        {
            var engPath = Path.Combine(reportsDir, "authorization", "engagement.json");
            if (!File.Exists(engPath)) return false;
            File.WriteAllText(Path.Combine(reportsDir, "engagement-data.js"),
                "/* Structured engagement authorization for the Authorization & Scope tab (from reports/authorization/engagement.json). */\n" +
                $"window.__ENGAGEMENT__={ReadAllTextShared(engPath)};\n");
            return true;
        });
        return dataFiles;
    }

    /// <summary>
    /// Writes one report data sidecar, isolating failures: returns 1 if the write reported producing a file, else
    /// 0; a thrown exception (e.g. a transient read race against the live MCP server) is logged and swallowed so
    /// the other sidecars still get written. <paramref name="write"/> returns void (always counts) or a bool.
    /// </summary>
    static int TryWriteSidecar(string what, Func<bool> write)
    {
        try { return write() ? 1 : 0; }
        catch (Exception ex) { Console.Error.WriteLine($"[bake-report] {what} skipped: {ex.Message}"); return 0; }
    }
    static int TryWriteSidecar(string what, Action write) => TryWriteSidecar(what, () => { write(); return true; });

    /// <summary>
    /// Reads a file another process may hold open for writing — the case's live MCP server appends to the audit
    /// CLEF during a session. <see cref="File.ReadAllText(string)"/> opens with <c>FileShare.Read</c>, which throws
    /// a sharing violation against that writer; opening with <c>FileShare.ReadWrite</c> lets the per-turn bake read
    /// the live log. (This is why the Stop-hook bake silently failed while a session was running.)
    /// </summary>
    static string ReadAllTextShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs);
        return sr.ReadToEnd();
    }

    /// <summary>Line-by-line shared read (see <see cref="ReadAllTextShared"/>) for the CLEF while it is being written.</summary>
    static IEnumerable<string> ReadLinesShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs);
        string? line;
        while ((line = sr.ReadLine()) is not null) yield return line;
    }

    // The case id names the per-case audit file and is substituted into report.html. Prefer the single
    // audit-&lt;id&gt;.clef in logs/ (authoritative — it is the SetCaseId value); fall back to the case dir name.
    static string ResolveCaseId(string caseDir, string logsDir)
    {
        if (Directory.Exists(logsDir))
        {
            var clefs = Directory.EnumerateFiles(logsDir, "audit-*.clef").ToList();
            if (clefs.Count == 1) return Path.GetFileNameWithoutExtension(clefs[0])["audit-".Length..];
        }
        return Path.GetFileName(caseDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
    }

    /// <summary>
    /// The set of preserved transcript files to reconstruct the case from: one per session id. preserve-chatlog
    /// writes the FULL transcript on each run, so multiple snapshots for one session id are cumulative, overlapping
    /// copies — keep only the latest (most complete) per session id. Accepts both the current stable name
    /// (<c>chatlog-&lt;sid&gt;.jsonl</c>) and the legacy timestamped name
    /// (<c>chatlog-&lt;sid&gt;-YYYYMMDDTHHMMSSZ.jsonl</c>), reducing both to the session id; distinct session ids are
    /// distinct sessions. The lexicographic max prefers the stable name (<c>'.' &gt; '-'</c>) and, among legacy
    /// names, the newest timestamp. Shared by the conversation and token-usage builders so both see the same data.
    /// </summary>
    static List<string> LatestChatlogFiles(string logsDir)
    {
        if (!Directory.Exists(logsDir)) return [];
        var rx = new Regex(@"^chatlog-(?<sid>.+?)(?:-\d{8}T\d{6}Z)?\.jsonl$");
        var latest = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var path in Directory.EnumerateFiles(logsDir, "chatlog-*.jsonl"))
        {
            var fn = Path.GetFileName(path);
            var sid = rx.Match(fn) is { Success: true } m ? m.Groups["sid"].Value : fn;
            if (!latest.TryGetValue(sid, out var cur) || string.CompareOrdinal(fn, Path.GetFileName(cur)) > 0)
                latest[sid] = path;
        }
        return latest.Values.OrderBy(f => Path.GetFileName(f), StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Reads every <c>logs/chatlog-*.jsonl</c> (the Claude Code transcripts the SessionEnd hook preserved) and
    /// builds the trimmed conversation the report's Conversation tab renders: per session, the user/assistant turns
    /// with their text / thinking / tool_use / tool_result blocks, capping tool input/output so the embed stays
    /// small. Returns the JSON array as a string, or <c>null</c> when there is no conversation to show.
    /// </summary>
    static string? BuildChatlogData(string logsDir)
    {
        var files = LatestChatlogFiles(logsDir);
        if (files.Count == 0) return null;

        static (string text, int trunc) Cap(string s, int n) => s.Length > n ? (s[..n], s.Length - n) : (s, 0);

        var sessions = new JsonArray();
        foreach (var file in files)
        {
            var turns = new JsonArray();
            foreach (var line in File.ReadLines(file))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                JsonNode? o; try { o = JsonNode.Parse(line); } catch { continue; }
                var type = o?["type"]?.GetValue<string>();
                if (type != "user" && type != "assistant") continue;

                var blocks = new JsonArray();
                var content = o?["message"]?["content"];
                if (content is JsonValue cv && cv.TryGetValue<string>(out var s))
                {
                    if (!string.IsNullOrWhiteSpace(s)) blocks.Add(new JsonObject { ["k"] = "text", ["text"] = s });
                }
                else if (content is JsonArray arr)
                {
                    foreach (var b in arr)
                    {
                        switch (b?["type"]?.GetValue<string>())
                        {
                            case "text" when b["text"]?.GetValue<string>() is string tx && !string.IsNullOrWhiteSpace(tx):
                                blocks.Add(new JsonObject { ["k"] = "text", ["text"] = tx }); break;
                            case "thinking" when b["thinking"]?.GetValue<string>() is string th && !string.IsNullOrWhiteSpace(th):
                                blocks.Add(new JsonObject { ["k"] = "thinking", ["text"] = th }); break;
                            case "tool_use":
                                var (inp, it) = Cap(b["input"]?.ToJsonString(JsDataOpts) ?? "", 4000);
                                blocks.Add(new JsonObject { ["k"] = "tool_use", ["name"] = b["name"]?.GetValue<string>(),
                                    ["id"] = b["id"]?.GetValue<string>(), ["input"] = inp, ["trunc"] = it }); break;
                            case "tool_result":
                                var rc = b["content"];
                                var raw = rc is JsonValue rv && rv.TryGetValue<string>(out var rs) ? rs : rc?.ToJsonString(JsDataOpts) ?? "";
                                var (txt, rt) = Cap(raw, 2000);
                                blocks.Add(new JsonObject { ["k"] = "tool_result", ["id"] = b["tool_use_id"]?.GetValue<string>(),
                                    ["err"] = b["is_error"]?.GetValue<bool>() ?? false, ["text"] = txt, ["trunc"] = rt }); break;
                        }
                    }
                }
                if (blocks.Count == 0) continue;
                turns.Add(new JsonObject
                {
                    ["role"] = type,
                    ["ts"] = o?["timestamp"]?.GetValue<string>(),
                    ["meta"] = o?["isMeta"]?.GetValue<bool>() ?? false,
                    ["side"] = o?["isSidechain"]?.GetValue<bool>() ?? false,
                    ["blocks"] = blocks,
                });
            }
            if (turns.Count > 0) sessions.Add(new JsonObject { ["file"] = Path.GetFileName(file), ["turns"] = turns });
        }
        return sessions.Count > 0 ? sessions.ToJsonString(JsDataOpts) : null;
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
            // Stable per-session filename, overwritten each run: the Stop hook fires after every agent turn, so a
            // timestamped name would accumulate one full-transcript copy per turn. Distinct sessions still get
            // distinct files, and BuildChatlogData dedups by session id (tolerating the legacy timestamped name).
            var dst = Path.Combine(logsDir, $"chatlog-{sessionId}.jsonl");
            File.Copy(src, dst, overwrite: true);
            Console.Out.WriteLine($"[preserve-chatlog] Preserved client chat log -> {dst}");

            WriteTokenUsage(src, logsDir, sessionId);

            // Bake the self-contained report now that the chat log is in place, so reports/report.html opens with
            // this session's findings/audit-trail/IOCs/accuracy/conversation by double-click. Best-effort: the
            // audit .clef may still be mid-flush from the (separate) MCP server process, so this stays re-runnable
            // via `bake-report`. baseDir is the case root ($CLAUDE_PROJECT_DIR).
            try
            {
                var n = BakeReport(baseDir);
                Console.Out.WriteLine($"[preserve-chatlog] Baked report ({n} data file(s)) -> {Path.Combine(baseDir, "reports", "report.html")}");
            }
            catch (Exception ex) { Console.Error.WriteLine($"[preserve-chatlog] Report bake skipped: {ex.Message}"); }
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
            var acc = AccumulateTokens([transcriptPath]);
            var summary = TokenSummaryObject(acc);
            // Prepend the single-session provenance fields the logs/ artifact carries (the report's aggregate
            // token-usage-data.js omits these).
            summary["sessionId"] = sessionId;
            summary["generatedUtc"] = DateTime.UtcNow.ToString("o");
            summary["transcript"] = transcriptPath;

            Directory.CreateDirectory(logsDir);
            var path = Path.Combine(logsDir, "token-usage.json");
            File.WriteAllText(path, summary.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Console.Out.WriteLine($"[preserve-chatlog] Token usage -> {path} (total {acc.Total:N0} tokens over {acc.Turns} turns)");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[preserve-chatlog] Token-usage summary failed: {ex.Message}");
        }
    }

    /// <summary>Accumulated token counts over one or more Claude Code transcripts, with a per-model breakdown.</summary>
    sealed class TokenAcc
    {
        public long Input, Output, CacheCreate, CacheRead;
        public int Turns;
        // model -> [turns, input, output, cacheCreate, cacheRead]
        public Dictionary<string, long[]> ByModel { get; } = new(StringComparer.Ordinal);
        public long Total => Input + Output + CacheCreate + CacheRead;
    }

    /// <summary>
    /// Sums the per-turn <c>usage</c> records of every <c>assistant</c> message across the given transcript(s) into
    /// a <see cref="TokenAcc"/> (overall totals + per-model). Lines that don't parse, non-assistant messages, and
    /// messages without a <c>usage</c> block are skipped. Tolerant of missing files.
    /// </summary>
    static TokenAcc AccumulateTokens(IEnumerable<string> transcriptPaths)
    {
        var a = new TokenAcc();
        foreach (var transcriptPath in transcriptPaths)
        {
            if (!File.Exists(transcriptPath)) continue;
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

                a.Input += i; a.Output += o; a.CacheCreate += cc; a.CacheRead += cr; a.Turns++;
                if (!a.ByModel.TryGetValue(model, out var m)) { m = new long[5]; a.ByModel[model] = m; }
                m[0]++; m[1] += i; m[2] += o; m[3] += cc; m[4] += cr;
            }
        }
        return a;
    }

    /// <summary>
    /// Renders a <see cref="TokenAcc"/> into the JSON shape the report (and <c>token-usage.json</c>) consume:
    /// <c>assistantTurns</c>, raw <c>totals</c>, the cached-vs-new <c>breakdown</c>, and a per-model table. Cached =
    /// <c>cache_read</c> (reused from the prompt cache, billed ~0.1x); new = fresh input + the one-time cache-write
    /// + output (billed at standard/output rates).
    /// </summary>
    static JsonObject TokenSummaryObject(TokenAcc a)
    {
        long totalInput = a.Input + a.CacheCreate + a.CacheRead;
        return new JsonObject
        {
            ["assistantTurns"] = a.Turns,
            ["totals"] = new JsonObject
            {
                ["input_tokens"] = a.Input,
                ["output_tokens"] = a.Output,
                ["cache_creation_input_tokens"] = a.CacheCreate,
                ["cache_read_input_tokens"] = a.CacheRead,
                ["total_tokens"] = a.Total,
            },
            ["breakdown"] = new JsonObject
            {
                ["cached_tokens"] = a.CacheRead,                       // cache_read — reused, billed ~0.1x
                ["new_tokens"] = a.Input + a.CacheCreate + a.Output,   // fresh input + cache-write + output
                ["new_input_tokens"] = a.Input + a.CacheCreate,        // fresh input (full + cache-write premium)
                ["output_tokens"] = a.Output,
                ["cache_read_fraction_of_input"] = totalInput > 0
                    ? Math.Round((double)a.CacheRead / totalInput, 4)
                    : 0.0,
            },
            ["byModel"] = new JsonObject(a.ByModel.Select(kv =>
                new KeyValuePair<string, JsonNode?>(kv.Key, new JsonObject
                {
                    ["turns"] = kv.Value[0],
                    ["input_tokens"] = kv.Value[1],
                    ["output_tokens"] = kv.Value[2],
                    ["cache_creation_input_tokens"] = kv.Value[3],
                    ["cache_read_input_tokens"] = kv.Value[4],
                }))),
        };
    }

    /// <summary>
    /// Builds the aggregate token-usage summary for the report's Conversation tab by summing over the same
    /// per-session transcripts the conversation is reconstructed from (so the numbers match what is shown). Returns
    /// null when there is no usage data (no transcripts / no assistant turns).
    /// </summary>
    static JsonObject? BuildTokenUsageData(string logsDir)
    {
        var files = LatestChatlogFiles(logsDir);
        var acc = AccumulateTokens(files);
        if (acc.Turns == 0) return null;
        var obj = TokenSummaryObject(acc);
        // Investigation wall-clock: sum each session transcript's own first->last span (summing per file avoids
        // counting the idle gap between a session ending and a later resume as "investigation time").
        var (ms, first, last) = TranscriptSpan(files);
        if (ms > 0)
        {
            obj["durationMs"] = ms;
            obj["firstActivityUtc"] = first;
            obj["lastActivityUtc"] = last;
        }
        return obj;
    }

    /// <summary>
    /// The investigation wall-clock from the preserved transcripts: for each session file the span between its
    /// earliest and latest entry <c>timestamp</c>, summed across sessions (so a gap between a session ending and a
    /// later resume is not counted). Returns total milliseconds plus the overall earliest/latest timestamps (ISO).
    /// </summary>
    static (long ms, string? first, string? last) TranscriptSpan(IEnumerable<string> paths)
    {
        long totalMs = 0;
        DateTime? globalFirst = null, globalLast = null;
        const System.Globalization.DateTimeStyles styles =
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal;
        foreach (var path in paths)
        {
            if (!File.Exists(path)) continue;
            DateTime? fileMin = null, fileMax = null;
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                JsonNode? n; try { n = JsonNode.Parse(line); } catch { continue; }
                var ts = n?["timestamp"]?.GetValue<string>();
                if (ts is null || !DateTime.TryParse(ts, null, styles, out var d)) continue;
                if (fileMin is null || d < fileMin) fileMin = d;
                if (fileMax is null || d > fileMax) fileMax = d;
            }
            if (fileMin is not null && fileMax is not null)
            {
                totalMs += (long)(fileMax.Value - fileMin.Value).TotalMilliseconds;
                if (globalFirst is null || fileMin < globalFirst) globalFirst = fileMin;
                if (globalLast is null || fileMax > globalLast) globalLast = fileMax;
            }
        }
        return (totalMs, globalFirst?.ToString("o"), globalLast?.ToString("o"));
    }

    /// <summary>
    /// Total server-side tool-execution time: the sum of <c>DurationMs</c> over every <c>command</c> event in the
    /// audit CLEF. Note this sums each tool call's own duration, so when the agent fanned calls out in parallel
    /// (Task.WhenAll) the sum can exceed the wall-clock tool time — the viewer clamps it to the total run time.
    /// Returns 0 when the file is absent or has no timed commands.
    /// </summary>
    static long SumToolCallMs(string clefPath)
    {
        if (!File.Exists(clefPath)) return 0;
        long total = 0;
        foreach (var line in ReadLinesShared(clefPath))   // shared read: the live server still writes the CLEF
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            JsonNode? n; try { n = JsonNode.Parse(line); } catch { continue; }
            if (n?["EventType"]?.GetValue<string>() != "command") continue;
            var d = n?["DurationMs"];
            if (d is null) continue;
            try { var ms = d.GetValue<double>(); if (ms > 0) total += (long)ms; } catch { }
        }
        return total;
    }

    /// <summary>Path to this running CLI assembly (empty for single-file publishes — fall back to the assembly dir).</summary>
    static string CliDllPath()
    {
        var dll = Assembly.GetEntryAssembly()?.Location;
        return string.IsNullOrEmpty(dll) ? Path.Combine(AssemblyLocation, "Camel.CLI.dll") : dll;
    }

    /// <summary>
    /// Builds the args array for the generated <c>.mcp.json</c>: launches this CLI assembly's investigation
    /// server verb (<c>dfir-server</c> or <c>pentest-server</c> per <c>--type</c>), carrying through the
    /// connection flags passed to <c>create-case</c> (any of --host/--user/--pass/--port implies --ssh unless
    /// --local was given) and the platform profile, so Claude Code starts Camel in the requested mode.
    /// </summary>
    static List<string> BuildServerArgs(CreateCaseOptions opts)
    {
        var verb = opts.Type == InvestigationType.PenTest ? "pentest-server" : "dfir-server";
        var args = new List<string> { CliDllPath(), verb };
        bool conn = !string.IsNullOrWhiteSpace(opts.Host) || !string.IsNullOrWhiteSpace(opts.User)
                    || !string.IsNullOrWhiteSpace(opts.Password) || opts.Port.HasValue;
        if (opts.Local) args.Add("--local");
        else if (opts.Ssh || conn) args.Add("--ssh");
        if (!string.IsNullOrWhiteSpace(opts.Host)) { args.Add("--host"); args.Add(opts.Host); }
        if (!string.IsNullOrWhiteSpace(opts.User)) { args.Add("--user"); args.Add(opts.User); }
        if (!string.IsNullOrWhiteSpace(opts.Password)) { args.Add("--pass"); args.Add(opts.Password); }
        if (opts.Port.HasValue) { args.Add("--port"); args.Add(opts.Port.Value.ToString()); }
        if (!string.IsNullOrWhiteSpace(opts.Platform)) { args.Add("--platform"); args.Add(opts.Platform); }
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
