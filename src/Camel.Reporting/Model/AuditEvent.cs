namespace Camel.Reporting.Model;

using System.Text.Json;

/// <summary>
/// A report-side read-model of one Serilog compact-JSON (CLEF) event from a case's <c>logs/audit-&lt;caseId&gt;.clef</c>.
/// Every line is one JSON object with the Serilog envelope (<c>@t</c>, <c>@mt</c>, optional <c>@l</c>) plus the
/// enriched properties the server stamps on it (<c>EventType</c>, <c>ExecutionId</c>, and per-event fields). This flattens
/// the object to string-valued fields so the reporting layer can count event types (for the attestation), project the
/// <c>vulnerability</c> events (for the report card), and trace <c>command</c> events back to an execution — without a
/// dependency on the server's logging model.
/// </summary>
public sealed class AuditEvent
{
    /// <summary>The event type (<c>command</c> / <c>execution</c> / <c>vulnerability</c> / <c>scope-violation</c> / …),
    /// or empty when the line carries no <c>EventType</c> property.</summary>
    public string EventType { get; init; } = "";

    /// <summary>The execution this event belongs to (the code-mode <c>Execute</c> that produced it), or empty.</summary>
    public string ExecutionId { get; init; } = "";

    /// <summary>The event timestamp (<c>@t</c>), or null if absent/unparseable.</summary>
    public DateTimeOffset? Timestamp { get; init; }

    /// <summary>The Serilog level (<c>@l</c>); Serilog omits it for <c>Information</c>, so that is the default here.</summary>
    public string Level { get; init; } = "Information";

    /// <summary>The rendered message: <c>@mt</c> is a template, so this is a best-effort fill of the named holes with
    /// the event's own properties (what a reader sees as the line's prose).</summary>
    public string Message { get; init; } = "";

    /// <summary>All scalar properties of the event, flattened to strings and keyed by property name (Serilog-cased,
    /// e.g. <c>Severity</c>, <c>Command</c>, <c>DurationMs</c>). Envelope keys (<c>@t</c>/<c>@mt</c>/<c>@l</c>) are excluded.</summary>
    public IReadOnlyDictionary<string, string> Fields { get; init; } =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The value of <paramref name="key"/>, or null if the event has no such property.</summary>
    public string? Get(string key) => Fields.TryGetValue(key, out var v) ? v : null;
}

/// <summary>Reads a CLEF (Serilog compact JSON) audit log into <see cref="AuditEvent"/> views. Tolerant: a malformed
/// line is skipped rather than aborting the whole report, and the file is opened shared so it can be read while the
/// case's MCP server is still appending to it (the same <c>FileShare.ReadWrite</c> the bake pipeline relies on).</summary>
public static class ClefReader
{
    /// <summary>Parse every well-formed line of <paramref name="clefPath"/> into events (empty list if the file is
    /// missing or unreadable).</summary>
    public static IReadOnlyList<AuditEvent> Read(string clefPath)
    {
        var events = new List<AuditEvent>();
        if (string.IsNullOrWhiteSpace(clefPath) || !File.Exists(clefPath)) return events;

        IEnumerable<string> lines;
        try { lines = ReadLinesShared(clefPath); }
        catch { return events; }

        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            var ev = TryParse(line);
            if (ev is not null) events.Add(ev);
        }
        return events;
    }

    private static IEnumerable<string> ReadLinesShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream);
        // Materialize inside the using so the shared handle stays open for the whole read.
        var all = new List<string>();
        string? line;
        while ((line = reader.ReadLine()) is not null) all.Add(line);
        return all;
    }

    private static AuditEvent? TryParse(string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string mt = "";
            DateTimeOffset? ts = null;
            string level = "Information";

            foreach (var prop in root.EnumerateObject())
            {
                switch (prop.Name)
                {
                    case "@t":
                        if (prop.Value.ValueKind == JsonValueKind.String &&
                            DateTimeOffset.TryParse(prop.Value.GetString(), out var parsed)) ts = parsed;
                        break;
                    case "@mt": mt = prop.Value.GetString() ?? ""; break;
                    case "@l": level = prop.Value.GetString() ?? "Information"; break;
                    case "@i": case "@r": case "@x": case "@tr": case "@sp": break; // other Serilog envelope keys
                    default:
                        fields[prop.Name] = Scalar(prop.Value);
                        break;
                }
            }

            return new AuditEvent
            {
                EventType = fields.GetValueOrDefault("EventType", ""),
                ExecutionId = fields.GetValueOrDefault("ExecutionId", ""),
                Timestamp = ts,
                Level = level,
                Message = RenderMessage(mt, fields),
                Fields = fields,
            };
        }
        catch { return null; }
    }

    // Flatten a JSON value to a display string. Objects/arrays are kept as their compact JSON (rare for the fields
    // the report reads, which are scalars) so nothing is silently lost.
    private static string Scalar(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => e.GetString() ?? "",
        JsonValueKind.Number => e.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null or JsonValueKind.Undefined => "",
        _ => e.GetRawText(),
    };

    // Best-effort fill of a Serilog message template's named holes ({Prop}, {@Prop}, {$Prop}) from the event's own
    // properties. Format specifiers ({X:u}) are dropped. Unknown holes are left as-is. Good enough for the report's
    // audit-trail prose; the structured fields remain the authoritative source.
    private static string RenderMessage(string template, IReadOnlyDictionary<string, string> fields)
    {
        if (string.IsNullOrEmpty(template) || !template.Contains('{')) return template;
        var sb = new System.Text.StringBuilder(template.Length + 32);
        for (int i = 0; i < template.Length; i++)
        {
            char c = template[i];
            if (c == '{')
            {
                if (i + 1 < template.Length && template[i + 1] == '{') { sb.Append('{'); i++; continue; }
                int end = template.IndexOf('}', i + 1);
                if (end < 0) { sb.Append(c); continue; }
                var token = template.Substring(i + 1, end - i - 1);
                var name = token.TrimStart('@', '$');
                int colon = name.IndexOf(':');
                if (colon >= 0) name = name[..colon];
                sb.Append(fields.TryGetValue(name, out var v) ? v : "{" + token + "}");
                i = end;
            }
            else if (c == '}' && i + 1 < template.Length && template[i + 1] == '}') { sb.Append('}'); i++; }
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
