namespace Camel;

using Microsoft.Extensions.Configuration;

using Camel.Intel;

/// <summary>
/// Aggregates the external knowledge-base facades bound to a session, over one shared
/// <see cref="KnowledgeBaseClient"/> (so caching and rate limits are shared across them). The intelligence-source
/// analogue of <see cref="CamelToolkitsApi"/> / <see cref="CamelPenTestToolkitsApi"/>: each facade is constructed
/// lazily on first access. Investigation-neutral — the red server binds the offensive facades (Nvd, …); the blue
/// server can bind threat-intel facades later over the same client.
/// </summary>
public class CamelKnowledgeApi : Runtime
{
    #region Constructors
    public CamelKnowledgeApi(IConfigurationRoot config)
    {
        client = new KnowledgeBaseClient(config);
    }
    #endregion

    #region Fields
    private readonly KnowledgeBaseClient client;
    private NvdKnowledgeBase? _nvd;
    #endregion

    #region Properties
    /// <summary>The shared knowledge-base client (configured sources / availability for the capability report).</summary>
    public KnowledgeBaseClient Client => client;

    /// <summary>NIST NVD CVE lookups (knowledge source — no scope/disclosure gate). Lazily constructed.</summary>
    public NvdKnowledgeBase Nvd => _nvd ??= new NvdKnowledgeBase(client);
    #endregion
}
