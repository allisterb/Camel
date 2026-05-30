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
    public void CanConnect()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        Assert.True(env.IsConnected);
    }

    [Fact]
    public void CanExecuteCommand()
    {
        SshAuditEnvironment env = new SshAuditEnvironment(EnvironmentMessageHandler, "camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        var result = env.ExecuteCommand("echo", "hello", out string output);

        Assert.Equal("hello", output.Trim());
    }
    LocalEnvironment le;
    string host, user, password;
    int port; 
}
