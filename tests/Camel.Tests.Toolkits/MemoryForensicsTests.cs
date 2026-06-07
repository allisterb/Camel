using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class MemoryForensicsTests : TestsRuntime
{
    public MemoryForensicsTests()
    {
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(LoadConfigFile("sshtestappsettings.json"));
    }

    [Fact]
    public void CanRunWindowsPsList()
    {
        var toolkit = new MemoryForensicsToolkit(localenv);
        var r = toolkit.WindowsPsList("D:\\Downloads\\Rocba-Memory\\Rocba-Memory.raw");
        Assert.NotNull(r);
    }
    LocalEnvironment localenv;
    AuditEnvironment sshenv;
}
