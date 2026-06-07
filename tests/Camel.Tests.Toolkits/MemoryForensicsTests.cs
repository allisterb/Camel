using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class MemoryForensicsTests : TestsRuntime
{
    public MemoryForensicsTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new MemoryForensicsToolkit(sshenv, sshconfig);    
    }

    [Fact]
    public void CanRunWindowsPsList()
    {
        //var toolkit = new MemoryForensicsToolkit(sshenv);
        var r = toolkit.WindowsPsList("~/memory-images/pat-2009-11-19.mddramimage");
        Assert.NotNull(r);
    }
    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    MemoryForensicsToolkit toolkit;
}
