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
    }
    #endregion

    #region Fields
    private readonly AuditEnvironment env;
    private new readonly IConfigurationRoot? config;
    private MemoryAnalysisToolkit? _memory;
    private DiskAnalysisToolkit? _disk;
    private WindowsAnalysisToolkit? _windows;
    private YaraToolkit? _yara;
    private TimelineToolkit? _timeline;
    private UnixToolsToolkit? _unix;
    #endregion

    #region Properties
    // All toolkits are constructed lazily on first access. Construction can run one-time tool provisioning
    // (Toolkit.InstallMissingTools downloads via wget/apt for WindowsAnalysis/Yara/Timeline), so eager
    // construction would make session creation — and any operation that touches the api — block on installs
    // for tools it never uses. Lazy construction means e.g. a mount (DiskAnalysis only) never pays for the
    // YARA rules pack or hayabusa.
    public MemoryAnalysisToolkit MemoryAnalysis => _memory ??= new MemoryAnalysisToolkit(env, config);
    public DiskAnalysisToolkit DiskAnalysis => _disk ??= new DiskAnalysisToolkit(env, config);
    public WindowsAnalysisToolkit WindowsAnalysis => _windows ??= new WindowsAnalysisToolkit(env, config);

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

    /// <summary>
    /// A collection of commonly used Unix utilities, currently the archive tools (<c>bunzip2</c>/<c>unzip</c>/
    /// <c>7z</c>) for uncompressing acquired disk and memory images. Constructed lazily on first use; first
    /// access requires a <c>Tools:UnixTools</c> config section. These tools need no provisioning (they ship
    /// with the base SIFT image).
    /// </summary>
    public UnixToolsToolkit UnixTools => _unix ??= new UnixToolsToolkit(env, config);
    #endregion
}
