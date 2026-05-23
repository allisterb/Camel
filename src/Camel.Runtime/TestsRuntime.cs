namespace Camel;

using System;

using Microsoft.Extensions.Configuration;

public class TestsRuntime : Runtime
{
    static TestsRuntime()
    {
        Runtime.WithFileAndConsoleLogging("Camel", "Tests", true);
        config = LoadConfigFile("testappsettings.json");      
        
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("Camel_API_TOKEN")))
        {
            Environment.SetEnvironmentVariable("Camel_API_TOKEN", config["ApiKey"], EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GRADIENT_AGENT_API_TOKEN")))
        {
            Environment.SetEnvironmentVariable("GRADIENT_AGENT_API_TOKEN", config["ApiKey2"], EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("Camel_SPACES_ENDPOINT")))
        {
            Environment.SetEnvironmentVariable("Camel_SPACES_ENDPOINT", config["SpacesEndpoint"], EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("Camel_SPACES_ACCESS_KEY_ID")))
        {
            Environment.SetEnvironmentVariable("Camel_SPACES_ACCESS_KEY_ID", config["SpacesAccessKeyId"], EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("Camel_SPACES_ACCESS_KEY_SECRET")))
        {
            Environment.SetEnvironmentVariable("Camel_SPACES_ACCESS_KEY_SECRET", config["SpacesAccessKeySecret"], EnvironmentVariableTarget.Process);
        }

        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("Camel_SPACES_SESSION_BUCKET")))
        {
            Environment.SetEnvironmentVariable("Camel_SPACES_SESSION_BUCKET", config["SpacesSessionBucket"], EnvironmentVariableTarget.Process);
        }
    }    
    static protected IConfigurationRoot config;
}

