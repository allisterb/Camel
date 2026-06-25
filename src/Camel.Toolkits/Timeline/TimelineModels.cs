namespace Camel.Toolkits.Models;

using System;
using System.Text.Json.Serialization;

// NOTE: TimelineEvent + EventTag are the SHARED canonical timeline types — consumed by the lean
// Camel.Inference core (which must not depend on DFIR), so they live in the neutral Camel.Toolkits.
// The DFIR-specific Timeline-toolkit outputs (hayabusa/plaso models) live in Camel.DFIR.Toolkits.

/// <summary>A single Plaso timeline event (from psort/psteal json_line output).</summary>
public class TimelineEvent
{
    /// <summary>Event time as a POSIX timestamp in microseconds (UTC).</summary>
    public long Timestamp { get; set; }
    [JsonPropertyName("timestamp_desc")] public string? TimestampDesc { get; set; }
    [JsonPropertyName("data_type")] public string? DataType { get; set; }
    public string? Parser { get; set; }
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    public string? Filename { get; set; }
    public string? Inode { get; set; }
    public string? Message { get; set; }
    [JsonPropertyName("sha256_hash")] public string? Sha256Hash { get; set; }
    [JsonPropertyName("md5_hash")] public string? Md5Hash { get; set; }

    /// <summary>
    /// The event's tagging-plugin tag, present only when the timeline was tagged (see
    /// <see cref="Camel.DFIR.Toolkits.TimelineToolkit.PsortTagAsync"/>) and the event matched a rule. Use
    /// <see cref="Labels"/> for the category names.
    /// </summary>
    public EventTag? Tag { get; set; }

    /// <summary>The category labels applied to this event by the tagging plugin (e.g. "application_execution"), or empty.</summary>
    [JsonIgnore]
    public string[] Labels => Tag?.Labels ?? [];

    /// <summary>The event time as a UTC <see cref="DateTimeOffset"/> (Plaso stores microseconds since epoch).</summary>
    [JsonIgnore]
    public DateTimeOffset Time => DateTimeOffset.FromUnixTimeMilliseconds(Timestamp / 1000);
}

/// <summary>A Plaso event-tag (from the psort tagging analysis plugin), carried inline on a tagged event.</summary>
public class EventTag
{
    /// <summary>The tag category names applied to the event (e.g. "application_execution", "login_attempt").</summary>
    [JsonPropertyName("labels")] public string[]? Labels { get; set; }
}
