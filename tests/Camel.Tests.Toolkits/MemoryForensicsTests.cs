using Camel.Environments;
using Camel.Toolkit;

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
    public void CanRunVolatility3Tool()
    {
        toolkit.Volatility3("-f D:\\Downloads\\Rocba-Memory\\Rocba-Memory.raw -r json windows.pslist", out string output);
        Assert.NotNull(output);
    }

    LocalEnvironment lenv;
    SshAuditEnvironment env;
    MemoryForensicsToolkit toolkit;
    string host, user, password;
    int port;
}
