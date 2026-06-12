namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Turns rendered timeline text (a <see cref="TextRenderer"/> event/window "sentence") into a fixed-length vector.
/// This is the seam between the pipeline and the representation: the zero-dependency <see cref="HashingEmbedder"/>
/// is the default baseline, and a learned sentence-transformer (all-MiniLM via ONNX, the path
/// <c>Camel.Search</c> already runs) drops in behind the same interface without touching the windowing, scoring,
/// or vector-store code. All embedders return L2-normalized vectors so cosine similarity is a plain dot product.
/// </summary>
public interface IEventEmbedder
{
    /// <summary>The dimensionality of the produced vectors.</summary>
    int Dimension { get; }

    /// <summary>Embeds one rendered text into an L2-normalized vector of length <see cref="Dimension"/>.</summary>
    float[] Embed(string text);

    /// <summary>Embeds a batch of texts (default: one call per item; ONNX embedders override for batched inference).</summary>
    float[][] Embed(IReadOnlyList<string> texts) => texts.Select(Embed).ToArray();
}

/// <summary>
/// A deterministic, dependency-free embedder: signed feature-hashing of the whitespace tokens in the rendered
/// text into a fixed-dimensional vector, then L2-normalized. It needs no model download and no training, yet
/// gives a genuine bag-of-behavioural-tokens representation — the right baseline to validate the windowing and
/// novelty-scoring spine before (and as a fallback after) a learned encoder is wired in. Uses FNV-1a, not
/// <see cref="object.GetHashCode"/>, so vectors are stable across processes and platforms.
/// </summary>
public sealed class HashingEmbedder : IEventEmbedder
{
    public HashingEmbedder(int dimension = 256)
    {
        if (dimension <= 0) throw new ArgumentOutOfRangeException(nameof(dimension));
        Dimension = dimension;
    }

    public int Dimension { get; }

    public float[] Embed(string text)
    {
        var v = new float[Dimension];
        foreach (var token in text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            uint h = Fnv1a(token);
            int idx = (int)(h % (uint)Dimension);
            v[idx] += (h & 0x8000_0000u) != 0 ? -1f : 1f;   // sign hashing keeps the estimate unbiased
        }
        VectorMath.NormalizeInPlace(v);
        return v;
    }

    private static uint Fnv1a(string s)
    {
        uint h = 2166136261;
        foreach (char c in s) { h ^= c; h *= 16777619; }
        return h;
    }
}

/// <summary>Small vector helpers shared by the embedders and the novelty scorer. Vectors are treated as dense float arrays.</summary>
public static class VectorMath
{
    /// <summary>L2-normalizes <paramref name="v"/> in place (no-op for a zero vector).</summary>
    public static void NormalizeInPlace(float[] v)
    {
        double sumSq = 0;
        for (int i = 0; i < v.Length; i++) sumSq += (double)v[i] * v[i];
        if (sumSq <= 0) return;
        float inv = (float)(1.0 / Math.Sqrt(sumSq));
        for (int i = 0; i < v.Length; i++) v[i] *= inv;
    }

    /// <summary>Dot product. For L2-normalized inputs this is the cosine similarity.</summary>
    public static float Dot(float[] a, float[] b)
    {
        if (a.Length != b.Length) throw new ArgumentException("vector length mismatch");
        float s = 0;
        for (int i = 0; i < a.Length; i++) s += a[i] * b[i];
        return s;
    }
}
