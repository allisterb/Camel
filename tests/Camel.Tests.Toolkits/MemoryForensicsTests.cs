using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class MemoryForensicsTests : TestsRuntime
{
    public MemoryForensicsTests()
    {
        lenv = new LocalEnvironment();
        if (config is null)
        {
            throw new Exception("Configuration not loaded");
        }
        host = GetRequiredValue(config, "Sift:Host");
        port = Int32.Parse(GetRequiredValue(config, "Sift:Port"));
        user = GetRequiredValue(config, "Sift:User");
        password = GetRequiredValue(config, "Sift:Password");
        env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), lenv);
        toolkit = new MemoryForensicsToolkit(lenv);
    }   

   

    [Fact]
    public void CanRunWindowsPsList()
    {
        var r = toolkit.WindowsPsList("D:\\Downloads\\Rocba-Memory\\Rocba-Memory.raw");
        Assert.NotNull(r);
    }
    LocalEnvironment lenv;
    SshAuditEnvironment env;
    MemoryForensicsToolkit toolkit;
    string host, user, password;
    int port;
}
