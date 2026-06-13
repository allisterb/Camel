namespace Camel.Workflows;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

// FOR500.3 — Shell Item analysis. Reconstructs a user's file- and folder-access history (and the external
// devices/shares it touched) by correlating the three shell-item artifact families: shortcut (LNK) files and
// Jump Lists in the Recent folder (files opened), and Shellbags in the user's registry (folders browsed).
public partial class WindowsAnalysisWorkflow
{
    #region Workflow methods
    /// <summary>
    /// Analyses the shell-item artifacts of a user profile (<paramref name="userProfileRoot"/>, e.g.
    /// <c>/mnt/img/Users/jdoe</c>) to reconstruct what the user opened and browsed — the FOR500.3 methodology.
    /// It parses the shortcut (<c>.lnk</c>) files and Jump Lists in <c>AppData\Roaming\Microsoft\Windows\Recent</c>
    /// (plus the Desktop) for <em>files opened</em>, and the Shellbags in the profile's <c>NTUSER.DAT</c> /
    /// <c>UsrClass.dat</c> for <em>folders browsed</em>. Each opened-file/folder reference that points at a
    /// non-system drive letter, a UNC share, or a named volume is also surfaced as
    /// <see cref="ShellItemReport.ExternalDeviceEvidence"/> — the bridge to USB / remote-share correlation (feed
    /// those serial numbers / volume names into <see cref="AnalyzeUsbDevicesAsync"/>). Findings are leads to triage.
    /// </summary>
    /// <param name="userProfileRoot">The mounted user profile directory (its Recent folder and hives are read).</param>
    /// <param name="hiveDirectory">Directory SBECmd recursively searches for the shellbag hives; defaults to
    /// <paramref name="userProfileRoot"/> (which contains NTUSER.DAT and, under AppData, UsrClass.dat).</param>
    public async Task<WorkflowResult<ShellItemReport>> AnalyzeShellItemsAsync(string userProfileRoot, string? hiveDirectory = null)
    {
        var root = userProfileRoot.TrimEnd('/');
        var recent = $"{root}/AppData/Roaming/Microsoft/Windows/Recent";
        var desktop = $"{root}/Desktop";

        using var _audit = AuditScope();
        using var op = Begin("Analyzing shell items for {0}", userProfileRoot);

        // Files opened: LNK shortcuts (Recent + Desktop) and Jump Lists (AutomaticDestinations). All three are
        // null-tolerant — a missing/empty source just contributes nothing.
        var lnks = (await WindowsAnalysis.LECmdDirectoryAsync(recent) ?? [])
            .Concat(await WindowsAnalysis.LECmdDirectoryAsync(desktop) ?? []).ToArray();
        var jumps = await WindowsAnalysis.JLECmdAsync($"{recent}/AutomaticDestinations") ?? [];
        var shellbags = await WindowsAnalysis.SBECmdAsync(hiveDirectory ?? root) ?? [];

        if (lnks.Length == 0 && jumps.Length == 0 && shellbags.Length == 0)
            return WorkflowResult<ShellItemReport>.Failure(
                $"No shell items parsed for '{userProfileRoot}'; check the path is a user profile with a Recent folder / registry hives.");

        var opened = lnks.Select(OpenedFromLnk).Concat(jumps.Select(OpenedFromJump))
            .Where(o => o.Path.Length > 0)
            .GroupBy(o => (o.Path, o.Source), StringTupleComparer)
            .Select(g => g.OrderByDescending(x => x.OpenedAround ?? DateTime.MinValue).First())
            .OrderByDescending(o => o.OpenedAround ?? DateTime.MinValue).ToArray();

        var folders = shellbags.Where(b => b.AbsolutePath is { Length: > 0 })
            .Select(b => new FolderAccessItem
            {
                Path = b.AbsolutePath!, ShellType = b.ShellType,
                FirstInteracted = b.FirstInteracted, LastInteracted = b.LastInteracted,
            })
            .GroupBy(f => f.Path, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
            .OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToArray();

        // External-device evidence: any opened-file or browsed-folder path on a non-C: drive / UNC / named volume.
        var external = opened.Select(o => ExternalRefOf(o.Path, o.Source, o.OpenedAround, o.VolumeSerialNumber))
            .Concat(folders.Select(f => ExternalRefOf(f.Path, "Shellbag", f.LastInteracted, null)))
            .Where(e => e is not null).Select(e => e!)
            .GroupBy(e => (e.Path, e.Source), StringTupleComparer).Select(g => g.First())
            .OrderBy(e => e.Path, StringComparer.OrdinalIgnoreCase).ToArray();

        op.Complete();
        var report = new ShellItemReport { OpenedFiles = opened, FoldersAccessed = folders, ExternalDeviceEvidence = external };
        return WorkflowResult<ShellItemReport>.Success(report,
            $"Recovered {opened.Length} opened-file reference(s) ({lnks.Length} LNK, {jumps.Length} jump-list), " +
            $"{folders.Length} browsed folder(s) (shellbags); {external.Length} reference(s) to external/removable/remote volumes" +
            (external.Length == 0 ? "." : $" (e.g. {string.Join(", ", external.Take(3).Select(e => e.Indicator))})."));
    }
    #endregion

    // An opened-file item from a LNK: prefer the resolved LocalPath, fall back to RelativePath.
    private static OpenedFileItem OpenedFromLnk(LnkFile l) => new()
    {
        Path = (l.LocalPath is { Length: > 0 } ? l.LocalPath : l.RelativePath) ?? "",
        Source = "LNK",
        TargetCreated = l.TargetCreated, TargetModified = l.TargetModified, TargetAccessed = l.TargetAccessed,
        FileSize = l.FileSize, Arguments = l.Arguments,
        Drive = DriveOf((l.LocalPath is { Length: > 0 } ? l.LocalPath : l.RelativePath)),
        OpenedAround = l.SourceModified ?? l.SourceAccessed ?? l.SourceCreated,
    };

    // An opened-file item from a Jump List entry.
    private static OpenedFileItem OpenedFromJump(JumpListEntry j) => new()
    {
        Path = (j.Path is { Length: > 0 } ? j.Path : j.RelativePath) ?? "",
        Source = "JumpList", AppId = j.AppIdDescription ?? j.AppId,
        TargetCreated = j.TargetCreated, TargetModified = j.TargetModified, TargetAccessed = j.TargetAccessed,
        FileSize = j.FileSize, Arguments = j.Arguments, VolumeSerialNumber = j.VolumeSerialNumber,
        Drive = DriveOf(j.Path is { Length: > 0 } ? j.Path : j.RelativePath),
        OpenedAround = j.LastModified ?? j.CreationTime,
    };

    // Flags a path that lives on a non-system volume: a drive letter other than C:, a UNC share, or a shellbag
    // "Volume name" / "My Computer\D:" style reference — the leads that tie file activity to USB keys and shares.
    private static ExternalDeviceRef? ExternalRefOf(string path, string source, DateTime? when, string? volSerial)
    {
        if (string.IsNullOrEmpty(path)) return null;
        string? indicator = null;
        if (path.StartsWith(@"\\")) indicator = "UNC/network share";
        else if (path.Length >= 2 && path[1] == ':' && char.ToUpperInvariant(path[0]) is var d and >= 'A' and <= 'Z' && d != 'C')
            indicator = $"non-system drive {char.ToUpperInvariant(path[0])}:";
        else if (path.Contains("\\\\", StringComparison.Ordinal)) indicator = "UNC/network share";
        if (indicator is null) return null;
        return new ExternalDeviceRef { Path = path, Indicator = indicator, Source = source, VolumeSerialNumber = volSerial, When = when };
    }

    // The drive letter (e.g. "C:") of a Windows path, or null for UNC / relative paths.
    private static string? DriveOf(string? path) =>
        path is { Length: >= 2 } && path[1] == ':' ? path[..2].ToUpperInvariant() : null;

    private static readonly IEqualityComparer<(string, string)> StringTupleComparer =
        new TupleOrdinalComparer();

    private sealed class TupleOrdinalComparer : IEqualityComparer<(string, string)>
    {
        public bool Equals((string, string) a, (string, string) b) =>
            string.Equals(a.Item1, b.Item1, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(a.Item2, b.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) t) =>
            HashCode.Combine(t.Item1.ToLowerInvariant(), t.Item2.ToLowerInvariant());
    }
}
