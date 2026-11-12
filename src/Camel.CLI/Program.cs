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

        // An MCP server on the stdio transport OWNS stdout -- it is the JSON-RPC channel itself. The logo and
        // the Serilog console sink put 24 lines of ANSI figlet art, the SSH host-key fingerprint and the
        // platform capability table on that channel ahead of the initialize response, and keep writing to it
        // for the rest of the session. A strict client rejects the stream outright: Antigravity registered the
        // server, read garbage, and reported no tools at all. Claude Code skips non-JSON lines, which is the
        // only reason this went unnoticed. Log to the file only; stdout stays protocol-pure.
        bool isStdioServer = !args.Contains("--http")
            && args.Any(a => a is "server" or "dfir-server" or "pentest-server");

        bool quietStdout = isHook || isStdioServer;
        if (!quietStdout) PrintLogo();
        if (quietStdout) Runtime.WithFileLogging("Camel", "CLI", args.Contains("--debug"));
        else Runtime.WithFileAndConsoleLogging("Camel", "CLI", args.Contains("--debug"));
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
        var briefName = opts.Harness switch
        {
            AgentHarness.Goose => "AGENTS.md",
            AgentHarness.Agy => "GEMINI.md",
            _ => "CLAUDE.md",
        };
        var claudePath = Path.Combine(caseDir, briefName);
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
            // The brief is authored for Claude Code, which registers the server in a root .mcp.json. Neutralize
            // that one harness-specific phrase for the harnesses that register it somewhere else.
            if (opts.Harness == AgentHarness.Goose)
                claude = claude.Replace("registered in `.mcp.json` (this directory)", "registered as the `camel` MCP extension");
            else if (opts.Harness == AgentHarness.Agy)
                claude = claude.Replace("registered in `.mcp.json` (this directory)", "registered in `.agents/plugins/camel/mcp_config.json` (this directory)");
            // Antigravity namespaces a server provided by a plugin as `<plugin>_<server>`, so the brief's
            // bare `camel` would send the agent to a ServerName that does not exist for call_mcp_tool and
            // read_resource. Both halves of the name are ours, so the result is deterministic.
            claude = claude.Replace("Camel MCP server (`camel`)",
                "Camel MCP server, which Antigravity registers under the namespaced name **`camel_camel`** "
                + "(`<plugin>_<server>`) — pass that exact name as the `ServerName` for `call_mcp_tool` and "
                + "`read_resource`");
            // Repoint the brief's mandatory "read the SDK reference first" block at whichever transport this
            // harness can actually serve (--sdk-docs). Resources is the default and needs no rewrite.
            claude = opts.SdkDocs switch
            {
                SdkDocMode.Files => BriefSdkDocsAsFiles(claude),
                SdkDocMode.Inline => BriefSdkDocsInline(claude, opts),
                _ => claude,
            };
            File.WriteAllText(claudePath, claude);
            Info($"Wrote {claudePath}{(opts.SdkDocs == SdkDocMode.Inline ? $" ({claude.Length / 1024} KB — SDK reference inlined)" : "")}");
        }

        // The sliced reference files go in whether or not the brief was rewritten just now, so re-running
        // create-case over a case whose brief is already filled in still refreshes them against this build.
        if (opts.SdkDocs == SdkDocMode.Files) WriteSdkDocFiles(opts, caseDir);

        // Harness-specific wiring. Claude Code and Antigravity get per-project config files (both use a root
        // .mcp.json; Claude adds .claude/settings.json, Antigravity a .agents/plugins/camel plugin). Goose instead
        // registers Camel as a per-session MCP extension via a run-goose launcher. The brief above and the report
        // viewer below are harness-agnostic.
        switch (opts.Harness)
        {
            case AgentHarness.Goose: WriteGooseLauncher(opts, caseDir, briefName); break;
            case AgentHarness.Agy: WriteAntigravityConfig(opts, caseDir); break;
            default: WriteClaudeConfig(opts, caseDir); break;
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
        var briefFull = Path.Combine(caseDir, briefName);
        switch (opts.Harness)
        {
            case AgentHarness.Goose:
                var launcher = OperatingSystem.IsWindows() ? "run-goose.cmd" : "run-goose.sh";
                AnsiConsole.MarkupLine($"[cyan]\nFill in the case details in {briefFull}. Set a model in {launcher} (e.g. --provider ollama --model <coding-model>), then run it to launch Camel under Goose.[/]");
                break;
            case AgentHarness.Agy:
                AnsiConsole.MarkupLine($"[cyan]\nFill in the case details in {briefFull}. Open the case directory in Antigravity (Desktop, or `agy`) to start - it discovers the .agents/plugins/camel plugin from here, which registers the server, and GEMINI.md by convention. Answer 'always allow ... in this project' the first time a camel tool is called; Antigravity records pre-approval itself and no file here can grant it up front.[/]");
                AnsiConsole.MarkupLine("[yellow]If Antigravity shows no Camel tools, check whether ~/.gemini/antigravity/mcp/camel/ exists: if it does not, Desktop never launched the server, so the folder was not opened as a project or not trusted - stale entries in ~/.gemini/config/projects/ for this folder are worth removing.[/]");
                break;
            default:
                AnsiConsole.MarkupLine($"[cyan]\nFill in the case details in {briefFull}. When you are ready launch Claude in that directory.[/]");
                break;
        }
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
        // The manual verb is a deliberate "regenerate the deliverables" action, so it also emits the PDF (the
        // automatic SessionEnd-only gate applies to the hook path, not to an explicit bake-report invocation).
        var pdf = BakePdfReport(caseDir);
        if (pdf is not null) AnsiConsole.MarkupLine($"[grey]PDF: {pdf}[/]");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Compiles the deterministic PDF deliverable (<c>reports/report.pdf</c>) from the case's <c>engagement.json</c>
    /// (pen-test) or absence of it (DFIR), the CLEF audit trail, and the agent-authored <c>report.md</c> /
    /// <c>accuracy.md</c>, via <see cref="Camel.Reporting.ReportBaker"/>. Deterministic and agent-independent — the
    /// compliance content is machine-built; only the narrative comes from the agent. Best-effort: never fails the
    /// caller (a session must still end cleanly). Returns the PDF path, or null when there is nothing to render yet.
    /// </summary>
    static string? BakePdfReport(string caseDir)
    {
        try
        {
            var path = Camel.Reporting.ReportBaker.Bake(caseDir);
            if (path is not null) Console.Out.WriteLine($"[bake-report] Baked PDF report -> {path}");
            return path;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[bake-report] PDF report skipped: {ex.Message}");
            return null;
        }
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

            // Two harnesses deliver this payload. Claude Code uses snake_case and exports $CLAUDE_PROJECT_DIR;
            // Antigravity uses camelCase (protojson), exports nothing, and runs the command with its working
            // directory set to the folder holding hooks.json -- which is NOT the case root. Antigravity does,
            // however, pass the opened workspace in `workspacePaths`, so each harness supplies what the other
            // lacks. Detect by payload shape rather than adding a flag the hook author could get wrong.
            var src = payload?["transcript_path"]?.GetValue<string>()
                      ?? payload?["transcriptPath"]?.GetValue<string>();
            bool agy = payload?["transcriptPath"] is not null || payload?["conversationId"] is not null;

            // Antigravity reads this hook's stdout as a JSON result object, so progress lines must NOT go there.
            var note = agy ? Console.Error : Console.Out;

            if (string.IsNullOrEmpty(src) || !File.Exists(src))
            {
                Console.Error.WriteLine($"[preserve-chatlog] transcript path missing or not found: {src}");
                if (agy) Console.Out.Write("{}");
                return Task.CompletedTask;
            }

            var baseDir = Environment.GetEnvironmentVariable("CLAUDE_PROJECT_DIR");
            if (string.IsNullOrWhiteSpace(baseDir))
                baseDir = payload?["workspacePaths"]?.AsArray().FirstOrDefault()?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(baseDir)) baseDir = Directory.GetCurrentDirectory();
            var logsDir = Path.Combine(baseDir, "logs");
            Directory.CreateDirectory(logsDir);

            var sessionId = payload?["session_id"]?.GetValue<string>()
                            ?? payload?["conversationId"]?.GetValue<string>() ?? "session";
            // Stable per-session filename, overwritten each run: the Stop hook fires after every agent turn, so a
            // timestamped name would accumulate one full-transcript copy per turn. Distinct sessions still get
            // distinct files, and BuildChatlogData dedups by session id (tolerating the legacy timestamped name).
            var dst = Path.Combine(logsDir, $"chatlog-{sessionId}.jsonl");
            if (agy)
            {
                // Different transcript shape: normalize it, and keep the original beside it for provenance under
                // a name the chatlog glob (chatlog-*.jsonl) deliberately does not match, so the raw copy is never
                // counted as a second conversation.
                var n = NormalizeAntigravityTranscript(src, dst, payload?["modelName"]?.GetValue<string>());
                if (n < 0) File.Copy(src, dst, overwrite: true);
                else note.WriteLine($"[preserve-chatlog] Normalized {n} Antigravity step(s) to the Claude transcript shape");
                File.Copy(src, Path.Combine(logsDir, $"transcript-{sessionId}.agy.jsonl"), overwrite: true);
            }
            else File.Copy(src, dst, overwrite: true);
            note.WriteLine($"[preserve-chatlog] Preserved client chat log -> {dst}");

            // Always summarise the PRESERVED copy: for Claude Code it is byte-identical to the source, and for
            // Antigravity it is the normalized form the accumulator can actually read.
            WriteTokenUsage(dst, logsDir, sessionId, note);

            // Bake the self-contained report now that the chat log is in place, so reports/report.html opens with
            // this session's findings/audit-trail/IOCs/accuracy/conversation by double-click. Best-effort: the
            // audit .clef may still be mid-flush from the (separate) MCP server process, so this stays re-runnable
            // via `bake-report`. baseDir is the case root ($CLAUDE_PROJECT_DIR).
            try
            {
                var n = BakeReport(baseDir);
                note.WriteLine($"[preserve-chatlog] Baked report ({n} data file(s)) -> {Path.Combine(baseDir, "reports", "report.html")}");
            }
            catch (Exception ex) { Console.Error.WriteLine($"[preserve-chatlog] Report bake skipped: {ex.Message}"); }

            // The PDF deliverable (reports/report.pdf) is the FINAL client artifact, not a per-turn live view, so it
            // is baked on SessionEnd only — never on the per-turn Stop hook (both hooks share this verb). The HTML
            // viewer above stays current every turn; the PDF is compiled once when the case closes.
            // Antigravity has no session-end event -- its `Stop` fires at the end of EVERY turn
            // (terminationReason NO_TOOL_CALL is a normal completion), so there is no moment here that means
            // "the case is closed". Baking the PDF each turn would be pure waste, so under that harness the HTML
            // viewer is kept current every turn and the PDF is left to a final `bake-report <case-dir>`, which
            // produces both. Claude Code does distinguish the two, so it still gets the PDF on SessionEnd.
            var hookEvent = payload?["hook_event_name"]?.GetValue<string>() ?? "";
            if (!agy && string.Equals(hookEvent, "SessionEnd", StringComparison.OrdinalIgnoreCase))
                BakePdfReport(baseDir);

            // An empty object = "no opinion": do not block the agent from stopping, inject nothing.
            if (agy) Console.Out.Write("{}");
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

    /// <summary>
    /// Converts an Antigravity transcript into the Claude Code transcript shape that <see cref="BuildChatlogData"/>
    /// and <see cref="AccumulateTokens"/> already parse, so the report viewer and the token summary need no
    /// per-harness special casing. Antigravity writes one flat record per execution step:
    /// <c>USER_EXPLICIT/USER_INPUT</c> for the operator's prompt, <c>MODEL/PLANNER_RESPONSE</c> for a model turn
    /// (its <c>thinking</c>, its <c>tool_calls</c>, and the step's token counts at the TOP level rather than under
    /// a <c>usage</c> object), and <c>MODEL/GENERIC</c> for the text a step produced — which, for a step that
    /// called a tool, is that tool's output. Returns the number of records written, or -1 when the input does not
    /// look like an Antigravity transcript (so the caller can fall back to copying it verbatim).
    /// </summary>
    static int NormalizeAntigravityTranscript(string src, string dst, string? modelName)
    {
        var outLines = new List<string>();
        string? lastToolUseId = null;
        int converted = 0, recognized = 0;

        foreach (var line in File.ReadLines(src))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            JsonNode? o; try { o = JsonNode.Parse(line); } catch { continue; }
            var type = o?["type"]?.GetValue<string>();
            if (type is null) continue;
            var ts = o["created_at"]?.GetValue<string>();
            var step = o["step_index"]?.GetValue<int>() ?? 0;

            if (type == "USER_INPUT")
            {
                recognized++;
                if (o["content"]?.GetValue<string>() is not string text || string.IsNullOrWhiteSpace(text)) continue;
                outLines.Add(new JsonObject
                {
                    ["type"] = "user",
                    ["timestamp"] = ts,
                    ["message"] = new JsonObject
                    {
                        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }),
                    },
                }.ToJsonString(JsDataOpts));
                converted++;
            }
            else if (type == "PLANNER_RESPONSE")
            {
                recognized++;
                var blocks = new JsonArray();
                if (o["thinking"]?.GetValue<string>() is string th && !string.IsNullOrWhiteSpace(th))
                    blocks.Add(new JsonObject { ["type"] = "thinking", ["thinking"] = th });
                if (o["content"]?.GetValue<string>() is string ct && !string.IsNullOrWhiteSpace(ct))
                    blocks.Add(new JsonObject { ["type"] = "text", ["text"] = ct });

                var i = 0;
                foreach (var tc in o["tool_calls"]?.AsArray() ?? new JsonArray())
                {
                    var id = $"s{step}_{i++}";
                    lastToolUseId = id;
                    blocks.Add(new JsonObject
                    {
                        ["type"] = "tool_use",
                        ["id"] = id,
                        ["name"] = tc?["name"]?.GetValue<string>(),
                        ["input"] = tc?["args"]?.DeepClone(),
                    });
                }
                if (blocks.Count == 0) continue;

                var msg = new JsonObject { ["content"] = blocks, ["model"] = modelName ?? "antigravity" };
                // The step's token counts sit at the top level here; the summariser reads a Claude-shaped `usage`,
                // whose cache_read field carries the bulk of a long agentic run.
                if (o["input_tokens"] is not null || o["output_tokens"] is not null)
                    msg["usage"] = new JsonObject
                    {
                        ["input_tokens"] = o["input_tokens"]?.GetValue<long>() ?? 0,
                        ["output_tokens"] = o["output_tokens"]?.GetValue<long>() ?? 0,
                        ["cache_read_input_tokens"] = o["cache_read_tokens"]?.GetValue<long>() ?? 0,
                        ["cache_creation_input_tokens"] = o["cache_creation_tokens"]?.GetValue<long>() ?? 0,
                    };

                outLines.Add(new JsonObject { ["type"] = "assistant", ["timestamp"] = ts, ["message"] = msg }
                    .ToJsonString(JsDataOpts));
                converted++;
            }
            else if (type == "GENERIC")
            {
                recognized++;
                if (o["content"]?.GetValue<string>() is not string text || string.IsNullOrWhiteSpace(text)) continue;
                // A tool's output, which Claude Code carries as a tool_result inside a user message. With no
                // preceding call it is ordinary model prose, so it stays an assistant text block.
                var isResult = lastToolUseId is not null;
                JsonObject block = isResult
                    ? new JsonObject { ["type"] = "tool_result", ["tool_use_id"] = lastToolUseId, ["content"] = text }
                    : new JsonObject { ["type"] = "text", ["text"] = text };
                outLines.Add(new JsonObject
                {
                    ["type"] = isResult ? "user" : "assistant",
                    ["timestamp"] = ts,
                    ["message"] = new JsonObject { ["content"] = new JsonArray(block) },
                }.ToJsonString(JsDataOpts));
                lastToolUseId = null;
                converted++;
            }
        }

        if (recognized == 0) return -1;
        File.WriteAllLines(dst, outLines);
        return converted;
    }

    static void WriteTokenUsage(string transcriptPath, string logsDir, string sessionId, TextWriter note)
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
            note.WriteLine($"[preserve-chatlog] Token usage -> {path} (total {acc.Total:N0} tokens over {acc.Turns} turns)");
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
    /// <summary>Claude Code harness: write the per-project <c>.mcp.json</c> (the `camel` stdio server with the
    /// connection flags baked in) and <c>.claude/settings.json</c> (code-mode policy — deny Bash, allow only the
    /// Camel MCP tools + scoped writes — plus the Stop/SessionEnd preserve-chatlog hooks). Existing files are left
    /// untouched.</summary>
    /// <summary>Write the root <c>.mcp.json</c> registering the `camel` stdio server (the CLI assembly launched with
    /// the connection flags baked in). Used by both the Claude Code and Antigravity harnesses, which read a
    /// per-project <c>.mcp.json</c> of the same shape. Existing file left untouched.</summary>
    static void WriteMcpJson(CreateCaseOptions opts, string caseDir)
    {
        var mcpPath = Path.Combine(caseDir, ".mcp.json");
        if (File.Exists(mcpPath))
        {
            Info($"{mcpPath} already exists — leaving it untouched.");
            return;
        }
        var node = JsonNode.Parse(ReadEmbedded("Camel.CLI.CaseTemplate.mcp.json"))!;
        node["mcpServers"]!["camel"]!["args"] =
            new JsonArray(BuildServerArgs(opts).Select(a => (JsonNode)JsonValue.Create(a)).ToArray());
        File.WriteAllText(mcpPath, node.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        Info($"Wrote {mcpPath}");
    }

    static void WriteClaudeConfig(CreateCaseOptions opts, string caseDir)
    {
        WriteMcpJson(opts, caseDir);

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
    }

    /// <summary>
    /// Antigravity (Google) harness. Antigravity discovers workspace customizations by walking from the opened
    /// folder up to the repository root looking for a <c>.agents/</c> directory — but it reads an MCP
    /// registration from only two places: the operator's global <c>~/.gemini/config/mcp_config.json</c>, or a
    /// PLUGIN's own <c>mcp_config.json</c>. A bare <c>.agents/mcp_config.json</c> is not one of them. That is why
    /// a case wired that way came up with no Camel tools and no <c>call_mcp_tool</c> at all, while the server was
    /// never even launched. Plugins, however, ARE found by that workspace walk, so wrapping the registration in
    /// one is the supported way to keep it per-case instead of polluting the global config:
    /// <list type="bullet">
    /// <item><c>.agents/plugins/camel/plugin.json</c> — the manifest marking the directory as a plugin.
    ///   Discovered plugins are enabled by default; an entry in <c>config.json</c>'s <c>plugins</c> map, which the
    ///   settings UI writes, overrides that.</item>
    /// <item><c>.agents/plugins/camel/mcp_config.json</c> — the registration itself: <c>command</c> + <c>args</c>
    ///   only, no <c>type</c> or <c>env</c>, args spelled with forward slashes, as the one reference project
    ///   proven to have been launched by Antigravity Desktop writes them (<c>reference/projects/inf-2</c>).</item>
    /// </list>
    /// The brief (<c>GEMINI.md</c>) is picked up as a rule by convention; no config file binds it.
    /// <para>NOT written: <c>.agents/settings.json</c>. Earlier revisions emitted one carrying
    /// <c>mcp.autoApprove</c>, <c>tools.disabled</c> and a tool-keyed permissions map, copied from an older
    /// reference project. No such file exists in this Antigravity's customization system — the documented types
    /// are rules, skills, plugins, hooks and MCP servers — and it was measurably inert: a run whose
    /// <c>tools.disabled</c> listed <c>run_command</c> shelled out to PowerShell on its very first step.
    /// Pre-approval is instead recorded by the client when the operator answers "always allow … in this project",
    /// landing in that project's record under <c>~/.gemini/config/projects/</c> as <c>mcp(camel/&lt;Tool&gt;)</c>.
    /// There is no file this command can write to grant it ahead of time.</para>
    /// <para>Diagnostic, when a generated case shows no Camel tools: Desktop caches a launched server's tool
    /// schemas under <c>~/.gemini/antigravity/mcp/&lt;server&gt;/</c> within the same minute it starts it. No
    /// such directory means Desktop never attempted the launch, so the fault is in it finding or trusting this
    /// configuration — not in the server, which would otherwise have written into the case's <c>logs/</c>.</para>
    /// </summary>

    /// <summary>Antigravity caps EACH rule file at 24,000 bytes and truncates the remainder on a line boundary,
    /// silently. The generated brief runs past that, and what falls off the end is the report-formatting and
    /// teardown guidance — including the rule never to write live malicious code into a deliverable, which on a
    /// webshell case is the difference between a report and a quarantined file.</summary>
    const int AgyRuleFileLimit = 24000;

    /// <summary>
    /// Keep <c>GEMINI.md</c> under <see cref="AgyRuleFileLimit"/> by moving its tail into the plugin's own rules
    /// file, which Antigravity loads whenever the plugin is enabled. The split falls on a top-level section
    /// boundary, so neither half ends mid-sentence, and the head keeps a pointer at the continuation so the agent
    /// is never left believing it has read the whole brief.
    /// </summary>
    static void SplitBriefForAntigravity(string caseDir, string pluginDir)
    {
        var briefPath = Path.Combine(caseDir, "GEMINI.md");
        if (!File.Exists(briefPath)) return;

        var text = File.ReadAllText(briefPath);
        if (Encoding.UTF8.GetByteCount(text) <= AgyRuleFileLimit) return;

        const string pointer = "\n> **This brief continues in `.agents/plugins/camel/rules/AGENTS.md`**, which Antigravity\n" +
                               "> loads alongside this file. That half is part of the brief and is not optional.\n";
        var margin = AgyRuleFileLimit - Encoding.UTF8.GetByteCount(pointer) - 512;

        var head = new StringBuilder();
        var tail = new StringBuilder();
        foreach (var section in Regex.Split(text, @"(?=^## )", RegexOptions.Multiline))
        {
            if (tail.Length == 0 && Encoding.UTF8.GetByteCount(head + section) <= margin) head.Append(section);
            else tail.Append(section);
        }
        // A single section bigger than the cap cannot be split on a boundary; leave the file alone and say so
        // rather than cut it mid-sentence ourselves.
        if (tail.Length == 0 || head.Length == 0)
        {
            Warn($"{briefPath} is over Antigravity's {AgyRuleFileLimit}-byte rule-file cap but has no top-level " +
                 "section boundary to split on, so it will be truncated. Shorten it by hand.");
            return;
        }

        File.WriteAllText(briefPath, head.ToString().TrimEnd() + "\n" + pointer);

        var rulesDir = Path.Combine(pluginDir, "rules");
        Directory.CreateDirectory(rulesDir);
        var rulesPath = Path.Combine(rulesDir, "AGENTS.md");
        File.WriteAllText(rulesPath,
            "# Case brief, continued\n\nThis is the remainder of this case's `GEMINI.md`. Antigravity caps each rule\n" +
            "file at 24,000 bytes, so the brief is split across the two files. Both halves apply in full.\n\n" +
            tail.ToString().TrimStart());

        Info($"Brief exceeded Antigravity's {AgyRuleFileLimit}-byte rule-file cap — moved its last " +
             $"{Encoding.UTF8.GetByteCount(tail.ToString())} bytes into {rulesPath}");

        var overflow = Encoding.UTF8.GetByteCount(File.ReadAllText(rulesPath));
        if (overflow > AgyRuleFileLimit)
            Warn($"{rulesPath} is {overflow} bytes, still over the cap, so it will itself be truncated. " +
                 "Shorten the brief by hand.");
    }

    static void WriteAntigravityConfig(CreateCaseOptions opts, string caseDir)
    {
        var pluginDir = Path.Combine(caseDir, ".agents", "plugins", "camel");
        Directory.CreateDirectory(pluginDir);

        SplitBriefForAntigravity(caseDir, pluginDir);

        if (opts.SdkDocs == SdkDocMode.Inline)
            Warn("--sdk-docs Inline is a poor fit for Antigravity: it caps each rule file at "
                 + AgyRuleFileLimit + " bytes, so nearly all of an inlined reference is discarded before the "
                 + "agent ever sees it. Use the default (Resources), or Files.");

        var manifestPath = Path.Combine(pluginDir, "plugin.json");
        if (File.Exists(manifestPath))
        {
            Info($"{manifestPath} already exists — leaving it untouched.");
        }
        else
        {
            File.WriteAllText(manifestPath,
                new JsonObject { ["name"] = "camel" }.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Info($"Wrote {manifestPath}");
        }

        var mcpPath = Path.Combine(pluginDir, "mcp_config.json");
        if (File.Exists(mcpPath))
        {
            Info($"{mcpPath} already exists — leaving it untouched.");
        }
        else
        {
            var mcp = new JsonObject
            {
                ["mcpServers"] = new JsonObject
                {
                    ["camel"] = new JsonObject
                    {
                        ["command"] = "dotnet",
                        ["args"] = new JsonArray(BuildServerArgs(opts)
                            .Select(a => (JsonNode)JsonValue.Create(a.Replace(Path.DirectorySeparatorChar, '/'))).ToArray()),
                    },
                },
            };
            File.WriteAllText(mcpPath, mcp.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            Info($"Wrote {mcpPath}");
        }

        var hooksPath = Path.Combine(pluginDir, "hooks.json");
        if (File.Exists(hooksPath))
        {
            Info($"{hooksPath} already exists — leaving it untouched.");
        }
        else
        {
            // Without this the case produces no viewable report at all: `reports/report.html` stays the
            // scaffolded template with its data placeholders unfilled, because nothing ever runs the bake. The
            // Claude Code case gets the same thing from `.claude/settings.json`'s Stop/SessionEnd hooks.
            //
            // `Stop` fires whenever the execution loop terminates, which for a normal turn is every turn, so the
            // handler must be cheap and idempotent -- `preserve-chatlog` is both (it overwrites one chat log per
            // conversation and re-bakes the HTML). A native plugin's hooks are read from the plugin ROOT, not
            // from a `hooks/` subdirectory. The command is absolute because the hook's working directory is the
            // folder holding this file, not the case; the handler recovers the case root from the payload's
            // `workspacePaths`.
            var hooks = new JsonObject
            {
                ["camel-preserve-and-bake"] = new JsonObject
                {
                    ["Stop"] = new JsonArray(
                        new JsonObject
                        {
                            ["type"] = "command",
                            ["command"] = $"dotnet \"{CliDllPath().Replace(Path.DirectorySeparatorChar, '/')}\" preserve-chatlog",
                            ["timeout"] = 120,
                        }),
                },
            };
            // Relaxed encoding so the quoted dll path stays readable as `"..."` rather than `"..."`:
            // this file is meant to be read and edited by the operator.
            File.WriteAllText(hooksPath, hooks.ToJsonString(new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            }));
            Info($"Wrote {hooksPath}");
        }

        // Antigravity's permission model is keyed by TOOL, not by path, so the clean-room path denies a Claude Code
        // case gets cannot be expressed here. Say so rather than let the operator assume the isolation is in force.
        var exposed = CleanRoomDenyPaths(caseDir).ToList();
        if (exposed.Count > 0)
        {
            Warn($"Antigravity scopes permissions by tool, not by path: the {exposed.Count} path(s) outside this " +
                 "case that a Claude Code case would deny (sibling cases, the Camel source tree) CANNOT be denied " +
                 "from the case directory. Desktop prompts before reading outside the opened folder, which is " +
                 "coarser and is the operator's own global setting; for a guaranteed clean-room run, create the " +
                 "case outside the Camel repository.");
        }
    }

    /// <summary>
    /// Absolute path globs the generated agent must not read, glob, grep or write — everything outside its own case
    /// directory that would invalidate a clean-room run: the Camel source tree, docs and reference material (the
    /// agent is meant to work from the SDK docs served over MCP, not from the implementation) and every sibling case
    /// directory (which holds another agent's findings for the same evidence). Forward slashes, as Antigravity's
    /// own per-project policies use. Only paths that exist are emitted, and never one containing the case itself;
    /// sibling cases created after this one are not covered, so re-run or extend the list by hand for a later case.
    /// </summary>
    static IEnumerable<string> CleanRoomDenyPaths(string caseDir)
    {
        var full = Path.GetFullPath(caseDir).TrimEnd(Path.DirectorySeparatorChar);
        string Norm(string p) => Path.GetFullPath(p).Replace('\\', '/').TrimEnd('/');
        // Compare on a separator boundary: a plain StartsWith would read sibling case 'ALIHADI' as a parent of
        // case 'ALIHADI-AGY' and silently drop the one deny that matters most.
        bool Outside(string p)
        {
            var q = Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar);
            return !full.Equals(q, StringComparison.OrdinalIgnoreCase)
                && !full.StartsWith(q + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        }

        // Sibling case directories: another agent's answers to the same questions.
        var parent = Path.GetDirectoryName(full);
        if (parent is not null && Directory.Exists(parent))
        {
            foreach (var sib in Directory.GetDirectories(parent).Where(Outside)) yield return $"{Norm(sib)}/**";
        }

        // The Camel install tree, found by walking up from this assembly to the repository root. Keyed on .git
        // rather than the solution file, which lives one level down in src/ — walking to the .sln would root this
        // at src/ and deny none of the source it is meant to hide.
        var root = new DirectoryInfo(Path.GetDirectoryName(CliDllPath()) ?? AssemblyLocation);
        while (root is not null && !Directory.Exists(Path.Combine(root.FullName, ".git"))
                                && !File.Exists(Path.Combine(root.FullName, ".git"))) root = root.Parent;
        if (root is null) yield break;

        foreach (var dir in new[] { "src", "tests", "docs", "reference", "ext", "tools", "benchmarks", "bin" })
        {
            var p = Path.Combine(root.FullName, dir);
            if (Directory.Exists(p) && Outside(p)) yield return $"{Norm(p)}/**";
        }
        foreach (var file in new[] { "CLAUDE.md", "AGENTS.md", "GEMINI.md", "Camel.sln", "Directory.Build.props" })
        {
            var p = Path.Combine(root.FullName, file);
            if (File.Exists(p)) yield return Norm(p);
        }
    }

    /// <summary>
    /// The SDK reference for an investigation type, taken from the very accessors the MCP server serves it from
    /// (<see cref="DFIRResources"/> / <see cref="PenTestResources"/>) so a generated copy can never drift from
    /// what an agent on the resource transport would read: the doc set (core + schema, sliceable by subject area),
    /// the generated map, the schema signpost, and the discipline document.
    /// </summary>
    static (SdkDocSet Set, string Index, string Signpost, string Discipline) SdkReference(InvestigationType type) =>
        type == InvestigationType.PenTest
            ? (CamelResources.PenTest, PenTestResources.SdkIndex(), PenTestResources.SdkSchema(), PenTestResources.SdkDiscipline())
            : (CamelResources.Dfir, DFIRResources.SdkIndex(), DFIRResources.SdkSchema(), DFIRResources.SdkDiscipline());

    /// <summary>
    /// <c>--sdk-docs Files</c>: write the SDK reference into <c>&lt;case&gt;/sdk/</c> with the same shape the server
    /// serves over MCP — <c>index.md</c>, <c>discipline.md</c>, <c>schema.md</c> (the signpost), the per-area
    /// <c>core/{Area}.md</c> and <c>schema/{Area}.md</c> slices, and the whole-document <c>core/all.md</c> /
    /// <c>schema/all.md</c>. An area with no section on one side is not written, exactly as it is not registered as
    /// a resource. Always overwritten: these are generated, not authored, and a stale slice is a wrong API.
    /// </summary>
    static void WriteSdkDocFiles(CreateCaseOptions opts, string caseDir)
    {
        var (set, index, signpost, discipline) = SdkReference(opts.Type);
        var sdkDir = Path.Combine(caseDir, "sdk");
        foreach (var sub in new[] { "core", "schema" }) Directory.CreateDirectory(Path.Combine(sdkDir, sub));

        var files = new List<(string Path, string Text)>
        {
            (Path.Combine(sdkDir, "index.md"), index),
            (Path.Combine(sdkDir, "discipline.md"), discipline),
            (Path.Combine(sdkDir, "schema.md"), signpost),
            (Path.Combine(sdkDir, "core", "all.md"), set.Core()),
            (Path.Combine(sdkDir, "schema", "all.md"), set.Schema()),
        };
        foreach (var area in set.Addressable)
        {
            foreach (var (kind, doc) in new[] { ("core", set.Core()), ("schema", set.Schema()) })
            {
                if (SdkDocs.Slice(doc, area.HeadingText) is string slice)
                    files.Add((Path.Combine(sdkDir, kind, $"{area.Name}.md"), slice));
            }
        }

        // The map and the preambles cross-reference the other documents BY RESOURCE URI (38 of them in the DFIR
        // map alone). Left alone, the agent reads sdk/index.md and is sent straight back to a transport this mode
        // exists because the harness cannot use, so the docs are repointed at each other exactly like the brief.
        foreach (var (path, text) in files) File.WriteAllText(path, SdkDocsAsFiles(text));
        Info($"Wrote {files.Count} SDK reference files to {sdkDir} " +
             $"({files.Sum(f => (long)f.Text.Length) / 1024} KB) — the brief reads these, not camel://sdk/*.");
    }

    /// <summary>Matches a <c>camel://sdk/...</c> resource URI in a brief, capturing the path after the scheme. The
    /// character class admits the <c>{Area}</c> placeholder the briefs use when naming the per-area resources.</summary>
    private static readonly Regex SdkResourceUri = new(@"camel://sdk/([A-Za-z0-9_/{}]+)", RegexOptions.Compiled);

    /// <summary>Matches a <c>camel-sdk-x</c> resource NAME in a brief or a reference document. The documents refer
    /// to each other by name as well as by URI ("see the ToolResult schema in camel-sdk-schema"), and a name left
    /// alone points at a transport the Files/Inline modes exist because the harness cannot use.</summary>
    private static readonly Regex SdkResourceName = new(@"camel-sdk-(index|core|schema|discipline)", RegexOptions.Compiled);

    /// <summary>The whole-document path behind a <c>camel-sdk-x</c> name (the bare core/schema names address the
    /// whole document, which is what <c>core/all</c> and <c>schema/all</c> hold).</summary>
    static string SdkNamedDoc(string name) => name switch
    {
        "index" => "index",
        "core" => "core/all",
        "schema" => "schema/all",
        _ => "discipline",
    };

    /// <summary><c>--sdk-docs Files</c>: repoint the brief's SDK-reference block from the <c>camel://sdk/*</c>
    /// resource URIs at the files <see cref="WriteSdkDocFiles"/> writes, preserving the read-only-what-you-need
    /// structure (the <c>{Area}</c> placeholder survives the rewrite as a path). The paired
    /// <c>**`camel-sdk-x`** (`camel://sdk/x`)</c> forms collapse to one path first, so the rewrite does not leave
    /// the same filename printed twice.</summary>
    static string BriefSdkDocsAsFiles(string brief) =>
        SdkDocsAsFiles(brief
            .Replace("read these MCP resources", "read these reference files, which are in the `sdk/` directory of this case")
            .Replace("**`camel-sdk-index`** (`camel://sdk/index`)", "**`sdk/index.md`**")
            .Replace("**`camel-sdk-discipline`** (`camel://sdk/discipline`)", "**`sdk/discipline.md`**")
            .Replace("`camel-sdk-index`", "`sdk/index.md`")
            .Replace("`camel-sdk-discipline`", "`sdk/discipline.md`")
            .Replace("read the three SDK resources", "read the SDK reference files named above")
            .Replace("resources are the authoritative reference", "files are the authoritative reference")
            .Replace("`camel-sdk-*`", "the `sdk/` reference files"));

    /// <summary>Rewrites every <c>camel://sdk/...</c> URI in a brief or a reference document as the path of the
    /// file holding it, relative to the case directory (which is where the agent is working, so the same path is
    /// correct from the brief and from inside <c>sdk/</c>).</summary>
    static string SdkDocsAsFiles(string text) =>
        SdkResourceName.Replace(
            SdkResourceUri.Replace(text, m => $"sdk/{m.Groups[1].Value}.md"),
            m => $"sdk/{SdkNamedDoc(m.Groups[1].Value)}.md");

    /// <summary>
    /// <c>--sdk-docs Inline</c>: append the whole SDK reference to the brief as appendices A–D and repoint every
    /// resource URI at the appendix that now holds it, so nothing is left for the agent to fetch. This is the
    /// fallback for a harness that serves neither resources nor file reads; it costs the agent the entire
    /// reference in every turn, which the per-area slicing exists to avoid, so <see cref="SdkDocMode.Files"/> is
    /// the better answer whenever the harness can read a file.
    /// </summary>
    static string BriefSdkDocsInline(string brief, CreateCaseOptions opts)
    {
        var (set, index, _, discipline) = SdkReference(opts.Type);
        var body = SdkResourceUri.Replace(brief
            .Replace("read these MCP resources",
                "read the SDK reference appended to the END of this file as appendices A-D - this harness may not " +
                "serve MCP resources, so the whole reference is inlined there and nothing needs fetching")
            .Replace("**`camel-sdk-index`** (`camel://sdk/index`)", "**Appendix A**")
            .Replace("**`camel-sdk-discipline`** (`camel://sdk/discipline`)", "**Appendix D**")
            .Replace("`camel-sdk-index`", "Appendix A")
            .Replace("`camel-sdk-discipline`", "Appendix D")
            .Replace("read the three SDK resources", "read appendices A and D below")
            .Replace("resources are the authoritative reference", "appendices are the authoritative reference")
            .Replace("`camel-sdk-*`", "the appendices"),
            m => InlineAppendix(m.Groups[1].Value));
        body = SdkResourceName.Replace(body, m => InlineAppendixOf(m.Groups[1].Value));

        var appendices = new (string Title, string Text)[]
        {
            ($"Appendix A - Camel JS SDK reference: the map ({set.Label})", index),
            ($"Appendix B - Camel JS SDK reference: methods ({set.Label} core)", set.Core()),
            ($"Appendix C - Camel JS SDK reference: model schemas ({set.Label})", set.Schema()),
            ($"Appendix D - {(opts.Type == InvestigationType.PenTest ? "engagement" : "forensic")} discipline", discipline),
        };
        var sb = new StringBuilder(body);
        foreach (var (title, text) in appendices)
        {
            // The appended documents cross-reference each other by resource URI too, so they get the same
            // rewrite — otherwise the map inside Appendix A still tells the agent to fetch camel://sdk/*.
            sb.Append("\n\n---\n\n# ").Append(title).Append("\n\n")
              .Append("*(The document below is included verbatim; its own headings start at level 2.)*\n\n")
              .Append(SdkResourceName
                  .Replace(SdkResourceUri.Replace(text, m => InlineAppendix(m.Groups[1].Value)),
                           m => InlineAppendixOf(m.Groups[1].Value))
                  .Replace("\n#", "\n##").TrimEnd())
              .Append('\n');
        }
        return sb.ToString();
    }

    /// <summary>
    /// Which inlined appendix holds a given <c>camel://sdk/</c> path. A per-area URI becomes a pointer to that
    /// area's SECTION of the appendix rather than the appendix alone: the briefs say "read `camel://sdk/core/{Area}`
    /// for the method detail and `camel://sdk/schema/{Area}` for the fields", and collapsing both to "Appendix B"
    /// and "Appendix C" turns that sentence into nonsense ("e.g. Appendix B + Appendix C"). Unrecognised paths
    /// fall back to the map, which inventories everything.
    /// </summary>
    /// <summary>The plain appendix label for a <c>camel-sdk-x</c> NAME, for prose that mentions the document
    /// rather than a specific area ("see the ToolResult schema in Appendix C").</summary>
    static string InlineAppendixOf(string name) => name switch
    {
        "index" => "Appendix A",
        "core" => "Appendix B",
        "schema" => "Appendix C",
        _ => "Appendix D",
    };

    static string InlineAppendix(string path) => path switch
    {
        "discipline" => "Appendix D",
        "index" or "core" => "Appendix A",
        "core/all" => "Appendix B in full",
        "schema" or "schema/all" => "Appendix C in full",
        _ when path.StartsWith("core/", StringComparison.Ordinal) => $"the {path["core/".Length..]} section of Appendix B",
        _ when path.StartsWith("schema/", StringComparison.Ordinal) => $"the {path["schema/".Length..]} section of Appendix C",
        _ => "Appendix A",
    };

    /// <summary>Goose harness: write a <c>run-goose.cmd</c>/<c>.sh</c> launcher that starts Goose with Camel
    /// registered as a per-session stdio MCP extension (<c>--with-extension</c>) and only that extension
    /// (<c>--no-profile</c>, so the user's global Goose tools don't leak in — the Goose analog of the Claude
    /// deny-Bash policy). The brief is passed as the <c>-i</c> instruction file; <c>--model</c>/<c>--provider</c>
    /// (if given) select the model, e.g. a local one via <c>--provider ollama</c>. After the run it bakes the
    /// report (Goose has no SessionEnd hook, so this is the once-at-the-end equivalent). Existing file untouched.
    /// MINIMAL: the extension command is space-joined; a Camel dll path or case dir containing spaces may need the
    /// quoting in the launcher adjusted by hand.</summary>
    static void WriteGooseLauncher(CreateCaseOptions opts, string caseDir, string briefName)
    {
        var win = OperatingSystem.IsWindows();
        var scriptPath = Path.Combine(caseDir, win ? "run-goose.cmd" : "run-goose.sh");
        if (File.Exists(scriptPath))
        {
            Info($"{scriptPath} already exists — leaving it untouched.");
            return;
        }

        var dll = CliDllPath();
        // The stdio extension command Goose will launch: `dotnet <dll> {dfir,pentest}-server <flags> --case-dir <abs>`.
        var ext = "camel:dotnet " + string.Join(" ", BuildServerArgs(opts));
        var model = "";
        if (!string.IsNullOrWhiteSpace(opts.Provider)) model += $" --provider {opts.Provider}";
        if (!string.IsNullOrWhiteSpace(opts.Model)) model += $" --model {opts.Model}";

        string body;
        if (win)
            body =
                "@echo off\r\n" +
                $"REM Camel case '{opts.CaseId}' under the Goose harness. Requires 'goose' on PATH.\r\n" +
                "REM Pick a model: edit the --provider/--model below (local models: --provider ollama --model <coding-model>),\r\n" +
                "REM or run 'goose configure' once to set a default. Then run this script to start the investigation.\r\n" +
                "setlocal\r\n" +
                "cd /d \"%~dp0\"\r\n" +
                $"goose run --no-profile --with-extension \"{ext}\"{model} -i {briefName} --max-turns 100 --max-tool-repetitions 5\r\n" +
                $"dotnet \"{dll}\" bake-report .\r\n";
        else
            body =
                "#!/usr/bin/env bash\n" +
                $"# Camel case '{opts.CaseId}' under the Goose harness. Requires 'goose' on PATH.\n" +
                "# Pick a model: edit the --provider/--model below (local models: --provider ollama --model <coding-model>),\n" +
                "# or run 'goose configure' once to set a default. Then run this script to start the investigation.\n" +
                "set -e\n" +
                "cd \"$(dirname \"$0\")\"\n" +
                $"goose run --no-profile --with-extension \"{ext}\"{model} -i {briefName} --max-turns 100 --max-tool-repetitions 5\n" +
                $"dotnet \"{dll}\" bake-report .\n";

        File.WriteAllText(scriptPath, body);
        if (!win) { try { File.SetUnixFileMode(scriptPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.OtherRead); } catch { /* best-effort chmod */ } }
        Info($"Wrote {scriptPath}");
    }

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
