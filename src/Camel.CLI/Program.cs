namespace Camel.CLI;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using CommandLine;
using CommandLine.Text;
using Microsoft.Extensions.AI;
using Spectre.Console;

using Camel.Environments;

internal class Program : Runtime
{
    static Program()
    {
        Runtime.WithFileAndConsoleLogging("Camel", "CLI", true);
        config = LoadConfigFile(Path.Combine(AssemblyLocation, "appsettings.json"));
        if (config is null) throw new Exception("Configuration not loaded.");
        environmentType = Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment"));
        auditEnvironment = le;
    }

    static async Task Main(string[] args)
    {
        PrintLogo();
        var parser = new Parser(with =>
        {
            with.CaseInsensitiveEnumValues = true;
            with.HelpWriter = null;
        });
        var result = parser.ParseArguments<ServerOptions, TestOptions>(args);
        try
        {
            await result.MapResult(
                
                async (ServerOptions opts) => await HandleServerArgs(opts),
                async (TestOptions opts) => await HandleTestArgs(opts),

                errs => HandleParseError(result, errs)
            );
        }        
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex);
        }
    }

    static async Task HandleServerArgs(ServerOptions opts)
    {
        if (config is null) throw new Exception("Configuration not loaded.");
        
        if (opts.Ssh)
        {
            config["SIFT:Environment"] = "Ssh";
        }
        else if (opts.Local)
        {
            config["SIFT:Environment"] = "Local";
        }

        if (Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment")) == EnvironmentType.Ssh)
        {
            // Fail fast: verify SSH connectivity once at startup (sessions then connect lazily on first use).
            host = GetRequiredValue(config, "SIFT:Host");
            if (AuditEnvironment.CreateFromConfig(config) is SshAuditEnvironment se && !se.IsConnected)
            {
                Error($"Could not connect to SSH environment on host {host}.");
                Environment.Exit(1);
            }           
        }
        else
        {
            Info($"Using local environment on host {Environment.MachineName}");
        }
        if (opts.Http)
        {
            Info("Starting Camel MCP Server in HTTP mode.");
            await CamelMCPServer.RunHttpAsync(config);
        }
        else
        {
            Info("Starting Camel MCP Server in stdio mode.");
            await CamelMCPServer.RunStdioAsync(config);
        }
    }

    static async Task HandleTestArgs(TestOptions options)
    {
        
    }
    static Task HandleParseError<T>(ParserResult<T> result, IEnumerable<CommandLine.Error> errs)
    {
        var helpText = HelpText.AutoBuild(result, h =>
        {
            h.AddOptions(result);
            return h;
        },
        e =>
        {
            return e;
        });
        Console.WriteLine(helpText);
        return Task.CompletedTask;
    }


    static void PrintLogo()
    {
        AnsiConsole.Write(new FigletText("Camel\n").Color(Color.Orange1));
    }
   
    static EnvironmentType environmentType = EnvironmentType.Local;
    static LocalEnvironment le = new LocalEnvironment();
    static AuditEnvironment auditEnvironment;
    static string user = "", host = "", password = "";
    static int port;

}
