using System;
using System.IO;
using System.Linq;

using Camel;
using Camel.Environments;
using Camel.Workflows;

namespace Camel.Tests.Workflows;

/// <summary>
/// Reproducer that generates the committed demo audit sample (demo/audit-sample/audit-srl-2018-rd01.clef) by
/// running three real rd-01 (SRL-2018) analysis executions through the actual workflow/toolkit/environment code
/// paths — the same paths the MCP server drives — under a case id, each in its own ExecutionId scope (exactly as
/// Execute does). Guarded by the CAMEL_GEN_AUDIT_SAMPLE env var so it is skipped in the normal suite;
/// run it explicitly to regenerate the sample. Requires the rd-01 C: image mounted at /mnt/rd01-c.
/// </summary>
public class AuditSampleGenerator : TestsRuntime
{
    const string CaseId = "srl-2018-rd01";
    const string Rd01 = "/mnt/rd01-c";
    static readonly string OutDir = "C:/Projects/Camel/demo/audit-sample";

    [Fact]
    public async Task GenerateSample()
    {
        if (Environment.GetEnvironmentVariable("CAMEL_GEN_AUDIT_SAMPLE") != "1") return; // skipped unless asked

        var cfg = LoadConfigFile("sshtestappsettings.json");
        var env = AuditEnvironment.CreateFromConfig(cfg);
        var api = new CamelToolkitsApi(env, cfg);
        var win = new WindowsAnalysisWorkflow(api);

        try { Directory.Delete(OutDir, true); } catch { }
        Runtime.WithAuditLog(OutDir);
        try
        {
            using (Runtime.PushAuditProperty("CaseId", CaseId))
            {
                // ── Execution 1: WMI fileless persistence ────────────────────────────────────────────────
                await Execution("7f3a9c21",
                    "const r = await WindowsAnalysisWorkflow.FindWmiPersistenceAsync(\n" +
                    "  '/mnt/rd01-c/Windows/System32/wbem/Repository/OBJECTS.DATA');\n" +
                    "log(JSON.stringify(r.Result.SuspiciousConsumers));",
                    async () =>
                    {
                        var r = await win.FindWmiPersistenceAsync($"{Rd01}/Windows/System32/wbem/Repository/OBJECTS.DATA");
                        var hit = r.Result?.SuspiciousConsumers.FirstOrDefault()
                                  ?? r.Result?.Consumers.Select(c => new Camel.Workflows.Models.WmiPersistenceEntry { Name = c.Name }).FirstOrDefault();
                        Print("WMI persistence", r.IsSuccess,
                            $"SuspiciousConsumers={r.Result?.SuspiciousConsumers.Length} Consumers={r.Result?.Consumers.Length} firstName={hit?.Name} cmd={hit?.Command}");
                        return r.IsSuccess;
                    });

                // ── Execution 2: execution evidence (Amcache) ────────────────────────────────────────────
                await Execution("2e8b14d6",
                    "const bins = await WindowsAnalysisWorkflow.GetExecutedBinariesFromAmcacheAsync(\n" +
                    "  '/mnt/rd01-c/Windows/appcompat/Programs/Amcache.hve');\n" +
                    "log(bins.Result.length + ' executed binaries');",
                    async () =>
                    {
                        var r = await win.GetExecutedBinariesFromAmcacheAsync($"{Rd01}/Windows/appcompat/Programs/Amcache.hve");
                        var sample = r.Result?.Where(e => e.FullPath is not null).Take(3).Select(e => e.FullPath);
                        Print("Amcache execution", r.IsSuccess,
                            $"entries={r.Result?.Length} sample=[{(sample is null ? "" : string.Join(" | ", sample))}]");
                        return r.IsSuccess;
                    });

                // ── Execution 3: $MFT filesystem records ─────────────────────────────────────────────────
                await Execution("9a4f7b03",
                    "const mft = await WindowsAnalysisToolkit.MFTECmdAsync('/tmp/rd01_mft_head');\n" +
                    "log(mft.length + ' MFT records');",
                    async () =>
                    {
                        const string mft = "/tmp/rd01_mft_head";
                        env.ExecuteCommand("head", $"-c 16000000 '{Rd01}/$MFT' > {mft}", out _, false);
                        var r = await api.WindowsAnalysis.MFTECmdAsync(mft);
                        Print("MFT records", r is not null, $"records={r?.Length} firstFile={r?.FirstOrDefault()?.FileName}");
                        return r is not null;
                    });
            }
        }
        finally { Runtime.CloseAndFlushAuditLog(); }
    }

    // Mirrors the server's Execute framing: push the ExecutionId, mark the execution boundary in the
    // audit trail (with the script the agent would have run), run the work, mark completion.
    static async Task Execution(string executionId, string script, Func<Task<bool>> work)
    {
        using var _exec = Runtime.PushAuditProperty("ExecutionId", executionId);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Runtime.AuditExecution("started", script);
        bool ok = await work();
        Runtime.AuditExecution("completed", success: ok, durationMs: sw.ElapsedMilliseconds);
    }

    static void Print(string finding, bool ok, string detail)
    {
        var line = $"[SAMPLE] {(ok ? "OK " : "ERR")} {finding}: {detail}";
        Console.WriteLine(line);
        File.AppendAllText(Path.Combine(OutDir, "_findings.txt"), line + "\n");
    }
}
