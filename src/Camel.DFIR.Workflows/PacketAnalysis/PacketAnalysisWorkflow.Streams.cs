namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Workflows.Models;

public partial class PacketAnalysisWorkflow
{
    // Lines in a reassembled stream worth surfacing (credentials / auth / commands).
    private static readonly Regex StreamHighlight = new(
        @"(?i)\b(authorization:|www-authenticate:|user(name)?\s*[=:]|pass(word)?\s*[=:]|USER\s|PASS\s|login|cmd\.exe|/bin/(ba)?sh|set-cookie:)",
        RegexOptions.Compiled);

    /// <summary>
    /// Reassembles a single stream (<paramref name="proto"/> = tcp/udp/http, <paramref name="index"/> = the stream
    /// number, e.g. from a <see cref="TriagePcapAsync"/> conversation) and returns its content with any
    /// credential/auth/command lines highlighted for quick review.
    /// </summary>
    /// <param name="pcap">Path to the capture file.</param>
    public async Task<WorkflowResult<StreamReport>> FollowStreamAsync(string pcap, string proto, int index)
    {
        using var _audit = AuditScope();
        using var op = Begin("Following {0} stream {1} in {2}", proto, index, pcap);

        var content = await PacketAnalysis.FollowStreamAsync(pcap, proto, index);
        if (content is null)
            return WorkflowResult<StreamReport>.Failure(
                $"Could not follow {proto} stream {index} in '{pcap}'; check the path and that the stream index exists.");

        var highlights = content.Split('\n')
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && StreamHighlight.IsMatch(l))
            .Distinct()
            .Take(50)
            .ToArray();

        op.Complete();
        var report = new StreamReport { Protocol = proto, Index = index, Content = content, Highlights = highlights };
        return WorkflowResult<StreamReport>.Success(report,
            $"Reassembled {proto} stream {index} ({content.Length} bytes)" +
            (highlights.Length == 0 ? "; no credential/command lines highlighted." : $"; {highlights.Length} highlighted line(s)."));
    }
}
