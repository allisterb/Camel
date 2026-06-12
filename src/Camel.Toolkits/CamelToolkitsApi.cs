namespace Camel;

using System;
using System.Linq;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits;

public class CamelToolkitsApi : Runtime
{
    #region Constructors
    public CamelToolkitsApi(AuditEnvironment env, IConfigurationRoot? config = null)
    {
        this.env = env;
        this.config = config;
        this.MemoryAnalysis = new MemoryAnalysisToolkit(env, config);
        this.DiskAnalysis = new DiskAnalysisToolkit(env, config);
        this.WindowsAnalysis = new WindowsAnalysisToolkit(env, config);
    }
    #endregion

    #region Fields
    private readonly AuditEnvironment env;
    private new readonly IConfigurationRoot? config;
    private YaraToolkit? _yara;
    private TimelineToolkit? _timeline;
    #endregion

    #region Properties
    public MemoryAnalysisToolkit MemoryAnalysis { get; }
    public DiskAnalysisToolkit DiskAnalysis { get; }
    public WindowsAnalysisToolkit WindowsAnalysis { get; }

    /// <summary>
    /// The YARA toolkit (classic <c>yara</c> file scanner + the bundled rules pack). Constructed lazily on
    /// first use so that callers and configs that never scan with YARA don't pay its construction cost or its
    /// <c>Tools:Yara</c> config requirement. First access requires a <c>Tools:Yara</c> section in the config.
    /// </summary>
    public YaraToolkit Yara => _yara ??= new YaraToolkit(env, config);

    /// <summary>
    /// The Timeline toolkit (Plaso <c>log2timeline</c>/<c>psort</c>/<c>pinfo</c>/<c>psteal</c>/<c>image_export</c>
    /// plus hayabusa). Constructed lazily on first use so that callers and configs that never build a timeline
    /// don't pay its construction cost or its <c>Tools:Timeline</c> config requirement (and so hayabusa is only
    /// provisioned when actually needed). First access requires a <c>Tools:Timeline</c> section in the config.
    /// </summary>
    public TimelineToolkit Timeline => _timeline ??= new TimelineToolkit(env, config);
    #endregion
}
