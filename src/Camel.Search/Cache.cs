namespace Camel.Search;

using System.ComponentModel;
using System.Text;
using System.Text.Json;

using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.Tokenizers;
using ZiggyCreatures.Caching.Fusion;
using ZiggyCreatures.Caching.Fusion.Serialization.SystemTextJson;


public static class CacheKeys
{
    public static string ToolEmbedding(string name) => $"tool-emb:{name}";
    public static string QueryEmbedding(string q) => $"query-emb:{q.ToLowerInvariant().Trim()}";
    public const string ToolSnapshot = "tool-emb-snapshot";
}

public static class CacheTags
{
    public const string Tools = "tool-embeddings";
}

public static class CacheServiceExtensions
{    
    public static IServiceCollection AddEmbeddingCache(this IServiceCollection services)
    {
        services
            .AddFusionCache()
            .WithDefaultEntryOptions(BuildDefaults())
            .WithSerializer(new FusionCacheSystemTextJsonSerializer());
        services.AddSingleton<EmbeddingCacheService>();
        return services;
    }
   
    private static FusionCacheEntryOptions BuildDefaults() =>
        new FusionCacheEntryOptions()
            .SetFailSafe(true, TimeSpan.FromHours(1), TimeSpan.FromSeconds(30))
            .SetFactoryTimeouts(TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(2));
}

public class EmbeddingCacheService(IFusionCache cache) : Runtime
{
    // Tool embeddings — cached indefinitely, tagged for bulk invalidation
    public ValueTask<float[]> GetOrComputeToolEmbeddingAsync(
        string toolName,
        Func<CancellationToken, Task<float[]>> factory,
        CancellationToken ct = default) =>
        cache.GetOrSetAsync<float[]>(
            CacheKeys.ToolEmbedding(toolName), factory,
            opt => opt.SetDuration(TimeSpan.MaxValue), tags: [CacheTags.Tools],
            ct)!;

    // Query embeddings — 30m L1 / 24h L2, fail-safe + factory timeouts
    public ValueTask<float[]> GetOrComputeQueryEmbeddingAsync(
        string query,
        Func<CancellationToken, Task<float[]>> factory,
        CancellationToken ct = default) =>
        cache.GetOrSetAsync<float[]>(
            CacheKeys.QueryEmbedding(query), factory,
            opt => opt
                .SetDuration(TimeSpan.FromMinutes(30))
                .SetDistributedCacheDuration(TimeSpan.FromHours(24))
                .SetFailSafe(true, TimeSpan.FromHours(4))
                .SetFactoryTimeouts(TimeSpan.FromMilliseconds(200), TimeSpan.FromSeconds(2)),
            ct)!;

    // Invalidate all tool embeddings at once if your code catalog changes
    public ValueTask InvalidateAllToolEmbeddingsAsync(CancellationToken ct = default)
    {
        Info("Invalidating all tool embeddings…");
        return cache.RemoveByTagAsync(CacheTags.Tools, token: ct);
    }

    // Load a snapshot containing the precomputed embeddings for the entire catalog
    public async Task<Dictionary<string, float[]>?> LoadSnapshotAsync(CancellationToken ct = default)
    {
        var r = await cache.TryGetAsync<Dictionary<string, float[]>>(CacheKeys.ToolSnapshot, token: ct);
        return r.HasValue ? r.Value : null;
    }

    // Save a snapshot of computed tool embeddings to prevent startup ONNX model calls
    public Task SaveSnapshotAsync(Dictionary<string, float[]> snapshot, CancellationToken ct = default)
    {
        Info($"Saving tool embedding snapshot ({snapshot.Count} tools)…");
        return cache.SetAsync(CacheKeys.ToolSnapshot, snapshot,
            opt => opt.SetDuration(TimeSpan.MaxValue).SetDistributedCacheDuration(TimeSpan.MaxValue),
            ct).AsTask();
    }
}

