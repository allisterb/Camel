namespace Camel.Tests.Environments;

using Camel.Environments;

public class SshEnvironmentTests : TestsRuntime
{        
    public SshEnvironmentTests()
    {
        if (config is null)
        {
            throw new Exception("Configuration not loaded");
        }
        host = GetRequiredValue(config, "Sift:Host");
        port = Int32.Parse(GetRequiredValue(config, "Sift:Port"));
        user = GetRequiredValue(config, "Sift:User");
        password = GetRequiredValue(config, "Sift:Password");
        le = new LocalEnvironment(EnvironmentMessageHandler);
    }
    [Fact]
    public void Test1()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        Assert.True(env.IsConnected);
    }

    LocalEnvironment le;
    string host, user, password;
    int port; 
}
