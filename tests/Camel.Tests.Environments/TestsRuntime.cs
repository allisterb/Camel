namespace Camel.Tests.Environments;

using System;

using Microsoft.Extensions.Configuration;

using Camel.Environments;

public class TestsRuntime : Runtime
{
    static TestsRuntime()
    {
        Runtime.WithFileAndConsoleLogging("Camel", "Tests", true);
        config = LoadConfigFile("testappsettings.json");
    }

    internal static void EnvironmentMessageHandler(object? sender, EnvironmentEventArgs e)
    {

        if (e.MessageType == EventMessageType.DEBUG)
        {
            Debug(e.Message);
        }
        else if (e.MessageType == EventMessageType.ERROR)
        {
            if (e.Exception != null)
            {
                Error(e.Exception, e.Message);
            }
            else
            {

                Error(e.Message);

            }
        }
        else
        {
            Info(e.Message);
        }


    }
  
}
