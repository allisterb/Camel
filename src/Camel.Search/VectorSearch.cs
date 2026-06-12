namespace Camel.Search;


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.Tokenizers;


public class VectorSearch : Runtime
{
    public VectorSearch()
    {
        if (!File.Exists(Path.Combine(AssemblyLocation, modelPath)))
        {
            if (!DownloadFile("model.onnx", new Uri(modelDownloadPath), Path.Combine(AssemblyLocation, modelPath)))
            {
                throw new Exception("Could not download all-MiniLM-L6-v2 model file from HuggingFace.");
            }
        }        
        services.AddEmbeddingCache();
        var sp = services.BuildServiceProvider();
        embeddingCache = sp.GetRequiredService<EmbeddingCacheService>();
        tokenizer = BertTokenizer.Create(SentenceEmbedder.OpenVocabStream(), new BertOptions
        {
            LowerCaseBeforeTokenization = true,
            ClassificationToken = "[CLS]",
            SeparatorToken = "[SEP]",
            PaddingToken = "[PAD]",
            UnknownToken = "[UNK]",
            MaskingToken = "[MASK]",
        });
        // Best-effort warm-load of any persisted tool-embedding snapshot (fire-and-forget; callers can await
        // EmbeddingCacheService.LoadSnapshotAsync directly when they need the result).
        _ = embeddingCache.LoadSnapshotAsync();
    }

    
    const string modelPath = "model.onnx";
    const string modelDownloadPath = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/onnx/model.onnx";
    const string vocabPath = "vocab.txt";
    const int maxTokens = 128;
    const int hiddenDim = 384; // MiniLM-L6-v2 outputs a 384-dimensional vector

    ServiceCollection services = new ServiceCollection();
    EmbeddingCacheService embeddingCache;
    BertTokenizer tokenizer;

}
