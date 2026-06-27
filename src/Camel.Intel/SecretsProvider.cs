namespace Camel.Intel;

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Resolves a knowledge-base secret (API key) by its reference name. Implementations read from a backing store
/// the agent cannot reach; the resolved value is injected into a request server-side and never bound into the JS
/// engine, the audit trail, or a report. A null result means "secret not set" — the KB then degrades to
/// unavailable rather than failing hard.
/// </summary>
public interface ISecretsProvider
{
    /// <summary>The secret value for <paramref name="keyRef"/>, or null when it is not set anywhere.</summary>
    string? Resolve(string keyRef);
}

/// <summary>
/// Default secret resolution, in priority order so secrets stay out of source control:
/// <list type="number">
/// <item>environment variable named <c>keyRef</c>;</item>
/// <item>a gitignored JSON secrets file (<c>{"KEY":"value"}</c>) at <c>Secrets:File</c> in config, defaulting to
/// <c>~/.camel/secrets.json</c>;</item>
/// <item>config key <c>Secrets:{keyRef}</c> (dev convenience only — discouraged, since config can be committed).</item>
/// </list>
/// </summary>
public sealed class DefaultSecretsProvider : ISecretsProvider
{
    private readonly IConfiguration? config;
    private readonly Lazy<IReadOnlyDictionary<string, string>> fileSecrets;

    public DefaultSecretsProvider(IConfiguration? config = null)
    {
        this.config = config;
        fileSecrets = new Lazy<IReadOnlyDictionary<string, string>>(() => LoadFile(config?["Secrets:File"]));
    }

    public string? Resolve(string keyRef)
    {
        if (string.IsNullOrWhiteSpace(keyRef)) return null;
        var env = Environment.GetEnvironmentVariable(keyRef);
        if (!string.IsNullOrWhiteSpace(env)) return env;
        if (fileSecrets.Value.TryGetValue(keyRef, out var v) && !string.IsNullOrWhiteSpace(v)) return v;
        var cfg = config?[$"Secrets:{keyRef}"];
        return string.IsNullOrWhiteSpace(cfg) ? null : cfg;
    }

    // Loads the secrets file (best-effort: a missing/unreadable/garbled file yields no secrets, never throws).
    private static IReadOnlyDictionary<string, string> LoadFile(string? path)
    {
        path = ExpandHome(string.IsNullOrWhiteSpace(path) ? DefaultPath() : path);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return new Dictionary<string, string>();
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path))
                   ?? new Dictionary<string, string>();
        }
        catch { return new Dictionary<string, string>(); }
    }

    private static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".camel", "secrets.json");

    private static string? ExpandHome(string? p) =>
        string.IsNullOrEmpty(p) ? p
        : p.StartsWith('~') ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + p[1..]
        : p;
}
