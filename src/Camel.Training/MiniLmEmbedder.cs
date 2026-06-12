namespace Camel.Training;
using Camel.Inference;

using System;
using System.Collections.Generic;

using Camel.Search;

/// <summary>
/// The learned-representation <see cref="IEventEmbedder"/>: embeds a rendered timeline sentence with the
/// all-MiniLM-L6-v2 sentence-transformer (384-d) via <see cref="SentenceEmbedder"/> (ONNX Runtime). It drops in
/// behind the interface wherever <see cref="HashingEmbedder"/> is used — the windowing, novelty-scoring and
/// vector-store code is unchanged — upgrading the bag-of-tokens baseline to a semantic encoder where
/// behaviourally-similar episodes embed nearby even when their surface tokens differ. The MiniLM model is
/// downloaded and cached on first use; dispose to release the native ONNX session.
/// </summary>
public sealed class MiniLmEmbedder : IEventEmbedder, IDisposable
{
    private readonly SentenceEmbedder embedder;

    /// <param name="modelDir">Where to cache the ONNX model (defaults to the assembly directory).</param>
    public MiniLmEmbedder(string? modelDir = null) => embedder = new SentenceEmbedder(modelDir);

    public int Dimension => embedder.Dimension;

    public float[] Embed(string text) => embedder.Embed(text);

    public float[][] Embed(IReadOnlyList<string> texts) => embedder.Embed(texts);

    public void Dispose() => embedder.Dispose();
}
