namespace Camel.Search;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using Microsoft.ML.Tokenizers;

/// <summary>A downloadable ONNX sentence-embedding model: where to fetch it, its output dimensionality, and any
/// task-instruction prefix / external vocabulary it needs.</summary>
/// <param name="Name">Human-readable model name (also used to name the cached vocab file).</param>
/// <param name="FileName">Local filename to cache the ONNX model under.</param>
/// <param name="ModelUrl">HuggingFace URL of the ONNX model.</param>
/// <param name="Dimension">Embedding dimensionality.</param>
/// <param name="Prefix">Task-instruction prefix prepended to every text (e.g. nomic's "classification: "), or null.</param>
/// <param name="VocabUrl">URL of the model's <c>vocab.txt</c>; null to use the BERT vocab embedded in this assembly.</param>
public sealed record EmbedderModel(string Name, string FileName, string ModelUrl, int Dimension,
    string? Prefix = null, string? VocabUrl = null)
{
    /// <summary>all-MiniLM-L6-v2 (384-d, sentence-similarity objective). Uses the embedded BERT vocab.</summary>
    public static readonly EmbedderModel MiniLmL6 = new(
        "all-MiniLM-L6-v2", "model.onnx",
        "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx", 384);

    /// <summary>nomic-embed-text-v1.5, 4-bit quantized (768-d; trained for retrieval/classification/clustering with
    /// a task-instruction prefix). Default prefix is "classification: "; ships its own vocab.</summary>
    public static readonly EmbedderModel NomicV15Q4 = new(
        "nomic-embed-text-v1.5-q4", "nomic-v1.5-q4.onnx",
        "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5/resolve/main/onnx/model_q4.onnx", 768,
        Prefix: "classification: ",
        VocabUrl: "https://huggingface.co/nomic-ai/nomic-embed-text-v1.5/resolve/main/vocab.txt");
}

/// <summary>
/// Embeds free text into a fixed-length sentence vector with an ONNX sentence-transformer, run locally via ONNX
/// Runtime. The model (see <see cref="EmbedderModel"/>) is downloaded from HuggingFace on first use and cached on
/// disk. Token embeddings are mean-pooled and L2-normalized (so cosine similarity is a plain dot product) — the
/// standard sentence-transformers recipe. Configurable across models (all-MiniLM by default; nomic-embed-text for
/// retrieval/classification with its task prefix) so the same plumbing serves tool-catalog retrieval and the DFIR
/// timeline encoder.
/// </summary>
public sealed class SentenceEmbedder : Runtime, IDisposable
{
    private const int MaxTokens = 512;

    private readonly InferenceSession session;
    private readonly BertTokenizer tokenizer;
    private readonly EmbedderModel model;
    private readonly string? prefix;

    /// <summary>The embedding dimensionality of the loaded model.</summary>
    public int Dimension => model.Dimension;

    /// <summary>The loaded model's name.</summary>
    public string Name => model.Name;

    /// <summary>Constructs the default embedder (all-MiniLM-L6-v2).</summary>
    public SentenceEmbedder(string? modelDir = null) : this(EmbedderModel.MiniLmL6, modelDir) { }

    /// <param name="model">The model to load/download.</param>
    /// <param name="modelDir">Cache directory for the model + vocab (defaults to the assembly directory).</param>
    /// <param name="prefixOverride">Overrides <see cref="EmbedderModel.Prefix"/> (e.g. "clustering: " vs the default).</param>
    public SentenceEmbedder(EmbedderModel model, string? modelDir = null, string? prefixOverride = null)
    {
        this.model = model;
        this.prefix = prefixOverride ?? model.Prefix;
        modelDir ??= AssemblyLocation;
        Directory.CreateDirectory(modelDir);

        var modelPath = Path.Combine(modelDir, model.FileName);
        if (!File.Exists(modelPath))
        {
            Info($"Downloading {model.Name} ONNX model to {modelPath} …");
            if (!DownloadFile(model.FileName, new Uri(model.ModelUrl), modelPath))
                throw new InvalidOperationException($"Failed to download the {model.Name} ONNX model from HuggingFace.");
        }
        session = new InferenceSession(modelPath);
        tokenizer = BertTokenizer.Create(OpenVocab(model, modelDir), new BertOptions { LowerCaseBeforeTokenization = true });
    }

    /// <summary>Embeds one text into an L2-normalized vector of length <see cref="Dimension"/>.</summary>
    public float[] Embed(string text)
    {
        var input = prefix is null ? (text ?? "") : prefix + (text ?? "");
        var ids = tokenizer.EncodeToIds(input, considerPreTokenization: true, considerNormalization: true);
        int n = Math.Clamp(ids.Count, 1, MaxTokens);

        var inputIds = new DenseTensor<long>([1, n]);
        var attention = new DenseTensor<long>([1, n]);
        var tokenTypes = new DenseTensor<long>([1, n]);
        for (int i = 0; i < n; i++) { inputIds[0, i] = ids[i]; attention[0, i] = 1; tokenTypes[0, i] = 0; }

        // Feed only the inputs this particular ONNX export declares (exports differ on token_type_ids).
        var feeds = new List<NamedOnnxValue>(3);
        foreach (var name in session.InputMetadata.Keys)
        {
            var tensor = name.Contains("mask", StringComparison.OrdinalIgnoreCase) ? attention
                       : name.Contains("type", StringComparison.OrdinalIgnoreCase) ? tokenTypes
                       : inputIds;
            feeds.Add(NamedOnnxValue.CreateFromTensor(name, tensor));
        }

        using var results = session.Run(feeds);
        int dim = model.Dimension;
        var vec = new float[dim];

        // Prefer the rank-3 token-embeddings output (mean-pool over the sequence); fall back to a rank-2 pooled output.
        var token = results.Select(r => r.AsTensor<float>()).FirstOrDefault(t => t.Dimensions.Length == 3);
        if (token is not null)
        {
            int seq = token.Dimensions[1], od = Math.Min(token.Dimensions[2], dim);
            for (int i = 0; i < seq; i++)
                for (int d = 0; d < od; d++) vec[d] += token[0, i, d];
            for (int d = 0; d < dim; d++) vec[d] /= seq;
        }
        else
        {
            var pooled = results.First().AsTensor<float>();
            int od = Math.Min(pooled.Dimensions[^1], dim);
            for (int d = 0; d < od; d++) vec[d] = pooled[0, d];
        }
        Normalize(vec);
        return vec;
    }

    /// <summary>Embeds a batch of texts (sequential per-item inference).</summary>
    public float[][] Embed(IReadOnlyList<string> texts) => texts.Select(Embed).ToArray();

    /// <summary>Opens the BERT vocabulary embedded in this assembly (the default tokenizer vocab).</summary>
    internal static Stream OpenVocabStream()
    {
        var asm = typeof(SentenceEmbedder).Assembly;
        var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("vocab.txt", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("Embedded 'vocab.txt' resource not found in Camel.Search.");
        return asm.GetManifestResourceStream(name)!;
    }

    // Resolves the tokenizer vocabulary: the embedded BERT vocab, or the model's own vocab downloaded + cached.
    private static Stream OpenVocab(EmbedderModel model, string modelDir)
    {
        if (model.VocabUrl is null) return OpenVocabStream();
        var vocabPath = Path.Combine(modelDir, model.Name + "-vocab.txt");
        if (!File.Exists(vocabPath) && !DownloadFile("vocab.txt", new Uri(model.VocabUrl), vocabPath))
            throw new InvalidOperationException($"Failed to download the vocabulary for {model.Name}.");
        return File.OpenRead(vocabPath);
    }

    private static void Normalize(float[] v)
    {
        double sumSq = 0;
        foreach (var x in v) sumSq += (double)x * x;
        if (sumSq <= 0) return;
        float inv = (float)(1.0 / Math.Sqrt(sumSq));
        for (int i = 0; i < v.Length; i++) v[i] *= inv;
    }

    public void Dispose() => session.Dispose();
}
