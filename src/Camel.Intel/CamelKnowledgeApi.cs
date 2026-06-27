namespace Camel;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Intel;

/// <summary>
/// Aggregates the external knowledge-base facades bound to a session, over one shared
/// <see cref="KnowledgeBaseClient"/> (so caching and rate limits are shared across them). The intelligence-source
/// analogue of <see cref="CamelToolkitsApi"/> / <see cref="CamelPenTestToolkitsApi"/>: each facade is constructed
/// lazily on first access. Investigation-neutral — the red server binds the offensive facades (Nvd, Shodan, …);
/// the blue server can bind threat-intel facades later over the same client. Target-keyed facades (Shodan) consult
/// the session's <see cref="AuditEnvironment"/> for the scope + external-disclosure gates.
/// </summary>
public class CamelKnowledgeApi : Runtime
{
    #region Constructors
    public CamelKnowledgeApi(AuditEnvironment env, IConfigurationRoot config)
    {
        this.env = env;
        // Pass the environment so CLI/File-transport KBs (e.g. searchsploit) can run on the platform (local/SSH).
        client = new KnowledgeBaseClient(config, env: env);
    }
    #endregion

    #region Fields
    private readonly AuditEnvironment env;
    private readonly KnowledgeBaseClient client;
    private NvdKnowledgeBase? _nvd;
    private KevKnowledgeBase? _kev;
    private EpssKnowledgeBase? _epss;
    private ExploitDbKnowledgeBase? _exploitDb;
    private OsvKnowledgeBase? _osv;
    private ShodanKnowledgeBase? _shodan;
    #endregion

    #region Properties
    /// <summary>The shared knowledge-base client (configured sources / availability for the capability report).</summary>
    public KnowledgeBaseClient Client => client;

    /// <summary>NIST NVD CVE lookups (knowledge source — no scope/disclosure gate). Lazily constructed.</summary>
    public NvdKnowledgeBase Nvd => _nvd ??= new NvdKnowledgeBase(client);

    /// <summary>CISA Known Exploited Vulnerabilities catalog lookups (knowledge source). Lazily constructed.</summary>
    public KevKnowledgeBase Kev => _kev ??= new KevKnowledgeBase(client);

    /// <summary>FIRST.org EPSS exploit-probability scores (knowledge source). Lazily constructed.</summary>
    public EpssKnowledgeBase Epss => _epss ??= new EpssKnowledgeBase(client);

    /// <summary>Exploit-DB lookups via the local <c>searchsploit</c> CLI (knowledge source, runs on the platform).
    /// Lazily constructed.</summary>
    public ExploitDbKnowledgeBase ExploitDb => _exploitDb ??= new ExploitDbKnowledgeBase(client);

    /// <summary>OSV.dev package-vulnerability lookups (knowledge source, HTTP POST). Lazily constructed.</summary>
    public OsvKnowledgeBase Osv => _osv ??= new OsvKnowledgeBase(client);

    /// <summary>Shodan host intelligence (target-keyed — gated by engagement scope + external-disclosure).
    /// Lazily constructed.</summary>
    public ShodanKnowledgeBase Shodan => _shodan ??= new ShodanKnowledgeBase(client, env);
    #endregion
}
