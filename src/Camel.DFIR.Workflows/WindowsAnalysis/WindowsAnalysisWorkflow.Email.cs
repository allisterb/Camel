namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Workflows.Models;

// FOR500.4 — E-mail archive analysis. Locates the host-based mail stores (Outlook PST and Exchange-cached OST)
// on a volume and reconstructs each store's messages at the header/metadata level (sender/recipient/subject/date
// and attachment names) — the offline-archive technique from the course (webmail/cloud mail is out of scope as it
// has no local archive). libpff's pffinfo provides the store metadata; libpst's readpst exports the messages.
public partial class WindowsAnalysisWorkflow
{
    #region Workflow methods
    /// <summary>
    /// Finds and analyses the Outlook/Exchange e-mail stores on a mounted volume — the FOR500.4 e-mail archive
    /// methodology. It locates every <c>.pst</c> (Personal Folders) and <c>.ost</c> (cached Exchange) store under
    /// <paramref name="volumeRoot"/> (or analyses the single store given by <paramref name="singleArchive"/>),
    /// reads each store's metadata with <c>pffinfo</c> (format, encryption), and exports its messages with
    /// <c>readpst</c>, parsing each to a <see cref="Camel.DFIR.Toolkits.Models.EmailMessage"/> (From/To/Cc/Subject/Date,
    /// X-Originating-IP, and attachment filenames). The per-archive summary surfaces the message count, folders,
    /// date span, and attachment-bearing messages — the leads for an insider/exfiltration timeline. Bodies are not
    /// extracted (triage altitude); orphan OSTs are handled the same as PSTs.
    /// </summary>
    /// <param name="volumeRoot">Mounted volume (or any directory) to search for PST/OST stores.</param>
    /// <param name="singleArchive">Analyse just this one PST/OST instead of searching (optional).</param>
    public async Task<WorkflowResult<EmailArchiveReport>> AnalyzeEmailArchivesAsync(string volumeRoot, string? singleArchive = null)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing e-mail archives under {0}", singleArchive ?? volumeRoot);

        string[] stores;
        if (singleArchive is not null)
            stores = [singleArchive];
        else
            stores = (await DiskAnalysis.FindFilesAsync(volumeRoot.TrimEnd('/'), ["*.pst", "*.ost"]))
                .Select(f => f.Path).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToArray();

        if (stores.Length == 0)
            return WorkflowResult<EmailArchiveReport>.Success(new EmailArchiveReport(),
                $"No PST/OST e-mail stores found under '{volumeRoot}'.");

        var archives = new List<EmailArchive>();
        foreach (var store in stores)
        {
            var info = (await WindowsAnalysis.PffInfoAsync(store)).Result;
            var export = (await WindowsAnalysis.ReadPstAsync(store)).Result;
            archives.Add(new EmailArchive
            {
                Path = store,
                Store = info,
                Messages = export?.Messages ?? [],
            });
        }

        op.Complete();
        var report = new EmailArchiveReport { Archives = archives.ToArray() };
        int totalMsgs = archives.Sum(a => a.MessageCount);
        int totalAttach = archives.Sum(a => a.MessagesWithAttachments);
        return WorkflowResult<EmailArchiveReport>.Success(report,
            $"Analyzed {archives.Count} e-mail store(s) ({totalMsgs} message(s), {totalAttach} with attachments): " +
            string.Join("; ", archives.Take(5).Select(a =>
                $"{System.IO.Path.GetFileName(a.Path)} [{a.Store?.ContentType ?? "?"}] {a.MessageCount} msg" +
                (a.LatestMessage is { } l ? $", latest {l:yyyy-MM-dd}" : ""))) + ".");
    }
    #endregion
}
