namespace Camel.Workflows;

using System;
using System.Linq;

using Camel.Workflows.Models;

public partial class PacketAnalysisWorkflow
{
    /// <summary>
    /// Carves transferred HTTP objects (responses — images, scripts, downloads) from a capture into
    /// <paramref name="outDir"/> via tshark's object exporter, and lists the HTTP requests seen (method/host/uri/
    /// user-agent) for context. Use this to recover files an attacker downloaded or exfiltrated over HTTP.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    /// <param name="outDir">Directory on the workstation to write carved objects into (created if missing).</param>
    public async Task<WorkflowResult<HttpObjectReport>> ExtractHttpObjectsAsync(string pcap, string outDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Extracting HTTP objects from {0} into {1}", pcap, outDir);

        var filesT = PacketAnalysis.ExportObjectsAsync(pcap, "http", outDir);
        var txT = PacketAnalysis.FieldsAsync(pcap, "http.request",
            ["http.request.method", "http.host", "http.request.uri", "http.user_agent"]);
        await Task.WhenAll(filesT, txT);

        var files = filesT.Result;
        if (files is null)
            return WorkflowResult<HttpObjectReport>.Failure(
                $"HTTP object export from '{pcap}' failed; check the path and that '{outDir}' is writable.");

        var transactions = (txT.Result ?? [])
            .Where(r => r.Any(c => c.Length > 0))
            .Select(r => new HttpTransaction
            {
                Method = Empty(r, 0), Host = Empty(r, 1), Uri = Empty(r, 2), UserAgent = Empty(r, 3),
            })
            .ToArray();

        op.Complete();
        var report = new HttpObjectReport { OutDir = outDir, CarvedFiles = files, Transactions = transactions };
        return WorkflowResult<HttpObjectReport>.Success(report,
            $"Carved {files.Length} HTTP object(s) into '{outDir}'; observed {transactions.Length} HTTP request(s)" +
            (transactions.Length == 0 ? "." : $" to {transactions.Select(t => t.Host).Distinct().Count()} host(s)."));
    }

    private static string? Empty(string[] r, int i) => i < r.Length && r[i].Length > 0 ? r[i] : null;
}
