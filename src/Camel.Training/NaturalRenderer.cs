namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Renders a <see cref="CanonicalEvent"/> as a short, natural-language sentence — an alternative to
/// <see cref="TextRenderer"/>'s compact token "salad" for embedders trained on prose (a sentence-transformer such
/// as all-MiniLM has no prior for tokens like "reg:shimcache loc:system32 macb:..b" but does understand
/// "A shimcache entry in the System32 directory was last written"). It is leakage-safe by construction: the
/// sentence is composed only from the canonical behavioural fields, never the raw path or message. NB: for a
/// bag-of-tokens embedder (<see cref="HashingEmbedder"/>) this is expected to be *worse* than the token render —
/// the added grammatical filler dilutes the discriminative tokens — so the renderer choice is embedder-specific.
/// </summary>
public static class NaturalRenderer
{
    /// <summary>Renders one event as a sentence, e.g. "Shortly after, a successful logon (event 4624) in the System32 directory was recorded, at 03:00."</summary>
    public static string Render(CanonicalEvent e)
    {
        var cadence = Cadence(e.DtPrev);
        var subject = Subject(e);
        var location = Location(e.Location);
        var verb = Verb(e.Macb);
        var time = $", at {e.HourOfDay:00}:00";

        var lead = cadence is null ? Capitalize(subject) : $"{cadence}, {subject}";
        return $"{lead}{location} {verb}{time}.";
    }

    /// <summary>Renders a window of events as a short paragraph (one sentence per event).</summary>
    public static string RenderSequence(IEnumerable<CanonicalEvent> events) => string.Join(" ", events.Select(Render));

    private static string Subject(CanonicalEvent e) => e.Source switch
    {
        SourceClass.EventLog => e.EventId is { } id ? $"a {EventName(id)} (event {id})" : "a Windows event log record",
        SourceClass.Registry => "a " + RegName(e.Reg),
        SourceClass.FileSystem => e.Ext is { Length: > 0 } x ? $"a {ExtName(x)}" : "a file",
        SourceClass.WebHistory => "a web browsing record",
        SourceClass.Lnk => "a shortcut file",
        SourceClass.Prefetch => "a program execution (prefetch) record",
        SourceClass.Log => "a log entry",
        _ => "an event",
    };

    private static string RegName(RegClass r) => r switch
    {
        RegClass.Shimcache => "application compatibility cache (shimcache) entry",
        RegClass.Amcache => "Amcache program record",
        RegClass.UserAssist => "UserAssist program-usage entry",
        RegClass.Run => "registry autorun (Run key) entry",
        RegClass.Service => "registry service entry",
        RegClass.Bam => "background activity moderator (BAM) entry",
        RegClass.MountPoints => "mounted-device (MountPoints2) entry",
        RegClass.UsbStor => "USB storage device entry",
        RegClass.TaskCache => "scheduled task entry",
        RegClass.Winlogon => "Winlogon entry",
        RegClass.Bagmru => "folder-access (BagMRU) entry",
        RegClass.Mru => "most-recently-used (MRU) entry",
        RegClass.Network => "network configuration entry",
        _ => "registry key",
    };

    private static string ExtName(string ext) => ext switch
    {
        "exe" => ".exe executable file",
        "dll" => ".dll library file",
        "ps1" => "PowerShell script file",
        "lnk" => "shortcut file",
        "sys" => ".sys driver file",
        "bat" or "cmd" => "batch script file",
        _ => $".{ext} file",
    };

    // A few high-value Windows event IDs get a meaningful phrase; the rest fall back to the generic subject.
    private static string EventName(int id) => id switch
    {
        4624 => "successful logon",
        4625 => "failed logon",
        4634 or 4647 => "logoff",
        4648 => "explicit-credential logon",
        4672 => "privileged logon",
        4688 => "process creation",
        4697 or 7045 => "service installation",
        4720 => "user-account creation",
        1102 => "security-log clear",
        7036 => "service state change",
        _ => "Windows event",
    };

    private static string Location(LocBucket loc) => loc switch
    {
        LocBucket.System32 => " in the System32 directory",
        LocBucket.SysWow64 => " in the SysWOW64 directory",
        LocBucket.WindowsOther => " in the Windows directory",
        LocBucket.ProgramFiles => " in Program Files",
        LocBucket.ProgramData => " in ProgramData",
        LocBucket.UsersProfile => " in a user profile",
        LocBucket.AppData => " in the user's AppData folder",
        LocBucket.Temp => " in a temporary folder",
        LocBucket.Recycle => " in the Recycle Bin",
        LocBucket.Network => " on a network share",
        LocBucket.Root => " at a drive root",
        _ => "",
    };

    private static string Verb(Macb m)
    {
        if (m == Macb.None) return "was recorded";
        var parts = new List<string>(4);
        if (m.HasFlag(Macb.Birth)) parts.Add("created");
        if (m.HasFlag(Macb.Modified)) parts.Add("modified");
        if (m.HasFlag(Macb.Accessed)) parts.Add("accessed");
        if (m.HasFlag(Macb.Changed)) parts.Add("had its metadata changed");
        return "was " + Join(parts);
    }

    private static string? Cadence(float dtPrev) => dtPrev switch
    {
        <= 0f => null,             // first event of the window — no lead-in
        < 2.5f => "Moments later",
        < 4.2f => "Seconds later",
        < 8.3f => "Minutes later",
        < 11.5f => "An hour later",
        _ => "Later",
    };

    private static string Join(List<string> parts) => parts.Count switch
    {
        0 => "",
        1 => parts[0],
        2 => $"{parts[0]} and {parts[1]}",
        _ => string.Join(", ", parts.Take(parts.Count - 1)) + ", and " + parts[^1],
    };

    private static string Capitalize(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
