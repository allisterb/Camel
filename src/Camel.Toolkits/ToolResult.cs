namespace Camel.Toolkits;

/// <summary>
/// The envelope every PenTest (red-team) toolkit method returns: either a successful <see cref="Value"/> or a
/// <see cref="FailureReason"/> explaining why the operation produced nothing — the tool was unavailable on the
/// platform, the command failed, the target did not respond, etc. The toolkit counterpart of the workflow layer's
/// <c>WorkflowResult&lt;T&gt;</c>.
///
/// It exists because the previous contract returned a bare <c>null</c> on failure, and the reason was only written
/// to the <i>server</i> log (via <c>Error(...)</c>) — invisible to the code-mode agent driving the <c>Execute</c>
/// tool, which just saw a null and could not tell "tool not installed" from "scan found nothing". This carries the
/// reason back into the script. Always check <see cref="Ok"/> before reading <see cref="Value"/>.
/// </summary>
public record ToolResult<T>
{
    /// <summary>True when the operation succeeded and <see cref="Value"/> is populated.</summary>
    public bool Ok { get; init; }

    /// <summary>The payload on success; <c>default</c>/null when <see cref="Ok"/> is false.</summary>
    public T? Value { get; init; }

    /// <summary>On failure, a human-readable reason the operation produced no value; null on success.</summary>
    public string? FailureReason { get; init; }

    /// <summary>A successful result carrying <paramref name="value"/>.</summary>
    public static ToolResult<T> Pass(T value) => new() { Ok = true, Value = value };

    /// <summary>A failed result carrying an explanatory <paramref name="reason"/> and no value.</summary>
    public static ToolResult<T> Fail(string reason) => new() { Ok = false, FailureReason = reason };

    /// <summary>Implicitly wraps a non-null value as a successful result, so a method can <c>return value;</c>
    /// directly on the success path (failures use the explicit <see cref="Fail"/>).</summary>
    public static implicit operator ToolResult<T>(T value) => Pass(value);
}
