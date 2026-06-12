namespace Camel.Training;
using Camel.Inference;

using System;
using System.Collections.Generic;

/// <summary>
/// Renders a <see cref="CanonicalEvent"/> to a compact, lower-cased "sentence" of behavioural tokens for the
/// off-the-shelf embedding path (a BERT/MiniLM sentence-transformer via <c>Camel.Search</c>). This is the
/// zero-training baseline representation: deterministic tokens drawn only from the canonical fields (never the
/// raw leaky path/message), so two behaviourally-similar events render to similar text and embed nearby.
/// </summary>
public static class TextRenderer
{
    /// <summary>Renders one event, e.g. "evtx record eid4624 loc:system32 macb:b dt:burst h:14".</summary>
    public static string Render(CanonicalEvent e)
    {
        var parts = new List<string>(9) { e.Source.ToString().ToLowerInvariant(), ShortDataType(e.DataType) };
        // A space after each "field:" keeps the field name a separate token from its value (e.g. "eid: 4624"
        // rather than "eid4624"), which a WordPiece/BERT tokenizer can actually segment — it matters for the
        // sentence-transformer embedders; for the bag-of-tokens HashingEmbedder it just splits into more tokens.
        if (e.EventId is { } id) parts.Add("eid: " + id);
        if (e.Reg != RegClass.None) parts.Add("reg: " + e.Reg.ToString().ToLowerInvariant());
        if (e.Location != LocBucket.Unknown) parts.Add("loc: " + e.Location.ToString().ToLowerInvariant());
        if (!string.IsNullOrEmpty(e.Ext)) parts.Add("ext: " + e.Ext);
        if (e.Macb != Macb.None) parts.Add("macb: " + MacbString(e.Macb));
        parts.Add("dt: " + DeltaBucket(e.DtPrev));
        parts.Add("h: " + e.HourOfDay);
        return string.Join(' ', parts);
    }

    /// <summary>Renders a window of events as a newline-free, space-joined sequence for sequence embedding.</summary>
    public static string RenderSequence(IEnumerable<CanonicalEvent> events) =>
        string.Join(" | ", events.Select(Render));

    // The last two colon-delimited segments of a data_type ("windows:registry:appcompatcache" -> "registry appcompatcache").
    private static string ShortDataType(string dataType)
    {
        var segs = dataType.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return segs.Length <= 2 ? dataType.Replace(':', ' ') : string.Join(' ', segs[^2..]);
    }

    private static string MacbString(Macb m)
    {
        Span<char> c = stackalloc char[4];
        c[0] = m.HasFlag(Macb.Modified) ? 'm' : '.';
        c[1] = m.HasFlag(Macb.Accessed) ? 'a' : '.';
        c[2] = m.HasFlag(Macb.Changed) ? 'c' : '.';
        c[3] = m.HasFlag(Macb.Birth) ? 'b' : '.';
        return new string(c);
    }

    // Coarse human-readable bucket for the ln-compressed inter-event delta (ln seconds): same-instant → days.
    private static string DeltaBucket(float dtPrev) => dtPrev switch
    {
        <= 0f => "same",          // ln(1+0)
        < 2.5f => "burst",        // < ~11 s
        < 4.2f => "sec",          // < ~66 s
        < 8.3f => "min",          // < ~75 min
        < 11.5f => "hour",        // < ~1.1 days
        _ => "day",
    };
}
