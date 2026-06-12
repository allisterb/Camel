namespace Camel.Training;
using Camel.Inference;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// A render tuned for sentence-transformer embedders, separating the two kinds of field a
/// <see cref="CanonicalEvent"/> carries:
/// <list type="number">
/// <item><b>Semantic fields</b> (source, registry artifact, location, extension, named event) are rendered as
/// real multi-word phrases — "application compatibility cache", "program files", "successful logon" — not the
/// enum spellings ("Shimcache", "ProgramFiles") that a WordPiece model has no vocabulary for.</item>
/// <item><b>No field-name labels</b> — the prose carries only meaning, no "loc:"/"reg:" noise tokens that repeat on
/// every event and dilute the embedding.</item>
/// <item><b>Structural / numeric fields</b> (unnamed event IDs, MACB flags, hour) are <em>bracket-delimited</em>
/// (<c>[eid 4688]</c>) so the model segments them as metadata instead of blending the digits into the sentence.</item>
/// </list>
/// Two entry points: <see cref="RenderSequence"/> (pure semantic) and <see cref="RenderSequenceWithStructural"/>
/// (semantic + the delimited structural tail).
/// </summary>
public static class SemanticRenderer
{
    /// <summary>Renders a window as semantic sentences only (one per event).</summary>
    public static string RenderSequence(IEnumerable<CanonicalEvent> events) =>
        string.Join(". ", events.Select(e => Render(e, structural: false)));

    /// <summary>Renders a window as semantic sentences, each followed by its bracket-delimited structural metadata.</summary>
    public static string RenderSequenceWithStructural(IEnumerable<CanonicalEvent> events) =>
        string.Join(". ", events.Select(e => Render(e, structural: true)));

    /// <summary>Renders one event: expanded semantic phrase, plus (optionally) its delimited structural tail.</summary>
    public static string Render(CanonicalEvent e, bool structural)
    {
        var words = new List<string>(5) { SourceWords(e.Source) };
        if (e.Reg != RegClass.None) words.Add(RegWords(e.Reg));
        if (e.Source == SourceClass.EventLog && EventName(e.EventId) is { } named) words.Add(named);
        // Only a real filesystem file's extension is meaningful; the .evtx/.pf/hive extension of an event-log /
        // prefetch / registry artifact is just its container format and must not leak into the sentence.
        if (e.Source == SourceClass.FileSystem && e.Ext is { Length: > 0 } x) words.Add(ExtWords(x));
        if (e.Location != LocBucket.Unknown) words.Add(LocationWords(e.Location));
        var text = string.Join(" ", words.Where(w => !string.IsNullOrEmpty(w)));

        if (structural)
        {
            var tail = new List<string>(3);
            if (e.Source == SourceClass.EventLog && EventName(e.EventId) is null && e.EventId is { } id) tail.Add($"[eid {id}]");
            if (e.Macb != Macb.None) tail.Add($"[{MacbString(e.Macb)}]");
            tail.Add($"[hour {e.HourOfDay}]");
            if (tail.Count > 0) text += " " + string.Join(" ", tail);
        }
        return text;
    }

    private static string SourceWords(SourceClass s) => s switch
    {
        SourceClass.EventLog => "windows event log",
        SourceClass.Registry => "registry",
        SourceClass.FileSystem => "file",
        SourceClass.WebHistory => "web browsing history",
        SourceClass.Lnk => "shortcut link",
        SourceClass.Prefetch => "program execution",
        SourceClass.Log => "system log",
        _ => "event",
    };

    private static string RegWords(RegClass r) => r switch
    {
        RegClass.Shimcache => "application compatibility cache",
        RegClass.Amcache => "installed program record",
        RegClass.UserAssist => "user program usage",
        RegClass.Run => "startup program",
        RegClass.Service => "system service",
        RegClass.Bam => "background activity",
        RegClass.MountPoints => "mounted device",
        RegClass.UsbStor => "usb storage device",
        RegClass.TaskCache => "scheduled task",
        RegClass.Winlogon => "logon process",
        RegClass.Bagmru => "folder browsing",
        RegClass.Mru => "recently used file",
        RegClass.Network => "network setting",
        _ => "registry setting",
    };

    private static string LocationWords(LocBucket loc) => loc switch
    {
        LocBucket.System32 or LocBucket.SysWow64 => "system folder",
        LocBucket.WindowsOther => "windows folder",
        LocBucket.ProgramFiles => "program files",
        LocBucket.ProgramData => "program data",
        LocBucket.UsersProfile => "user profile",
        LocBucket.AppData => "application data folder",
        LocBucket.Temp => "temporary folder",
        LocBucket.Recycle => "recycle bin",
        LocBucket.Network => "network share",
        LocBucket.Root => "drive root",
        _ => "",
    };

    private static string ExtWords(string ext) => ext switch
    {
        "exe" => "executable program",
        "dll" => "code library",
        "ps1" => "powershell script",
        "lnk" => "shortcut",
        "sys" => "device driver",
        "bat" or "cmd" => "batch script",
        _ => ext,
    };

    private static string? EventName(int? id) => id switch
    {
        4624 => "successful logon",
        4625 => "failed logon",
        4634 or 4647 => "logoff",
        4648 => "explicit credential logon",
        4672 => "privileged logon",
        4688 => "process creation",
        4697 or 7045 => "service installation",
        4720 => "user account creation",
        1102 => "security log cleared",
        7036 => "service state change",
        _ => null,
    };

    private static string MacbString(Macb m)
    {
        Span<char> c = stackalloc char[4];
        c[0] = m.HasFlag(Macb.Modified) ? 'm' : '.';
        c[1] = m.HasFlag(Macb.Accessed) ? 'a' : '.';
        c[2] = m.HasFlag(Macb.Changed) ? 'c' : '.';
        c[3] = m.HasFlag(Macb.Birth) ? 'b' : '.';
        return new string(c);
    }
}
