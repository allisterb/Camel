namespace Camel.Training;
using Camel.Inference;

using System;
using System.Collections.Generic;

using Camel.Search;

/// <summary>
/// An <see cref="IEventEmbedder"/> backed by <c>nomic-embed-text-v1.5</c> (4-bit quantized ONNX, 768-d). Unlike
/// the sentence-<em>similarity</em> objective of all-MiniLM (<see cref="MiniLmEmbedder"/>), nomic is trained for
/// retrieval / <em>classification</em> / clustering and takes a task-instruction prefix — so it is the better fit
/// for the action-classification and triage tasks, used with the <see cref="NaturalRenderer"/> (it expects prose,
/// not token salad). Drops in behind the interface unchanged. The model (~165 MB) and its vocabulary are
/// downloaded and cached on first use; dispose to release the native ONNX session.
/// </summary>
public sealed class NomicEmbedder : IEventEmbedder, IDisposable
{
    private readonly SentenceEmbedder embedder;

    /// <param name="modelDir">Where to cache the ONNX model + vocab (defaults to the assembly directory).</param>
    /// <param name="prefix">The nomic task-instruction prefix — "classification: " (default), "clustering: ",
    /// or "search_document: " for retrieval/novelty. Must match the downstream task.</param>
    public NomicEmbedder(string? modelDir = null, string prefix = "classification: ") =>
        embedder = new SentenceEmbedder(EmbedderModel.NomicV15Q4, modelDir, prefix);

    public int Dimension => embedder.Dimension;

    public float[] Embed(string text) => embedder.Embed(text);

    public float[][] Embed(IReadOnlyList<string> texts) => embedder.Embed(texts);

    public void Dispose() => embedder.Dispose();
}
