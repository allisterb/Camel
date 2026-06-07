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
        if (environmentType == EnvironmentType.Ssh)
        {
            host = GetRequiredValue(config, "Sift:Host");
            port = Int32.Parse(GetRequiredValue(config, "Sift:Port"));
            user = GetRequiredValue(config, "Sift:User");
            password = GetRequiredValue(config, "Sift:Password");
            auditEnvironment = new SshAuditEnvironment("camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), le);
        }
        if (opts.Http)
        {
            AnsiConsole.MarkupLine("[green]Starting Camel MCP Server in HTTP mode...[/]");
            await CamelMCPServer.RunHttpAsync(auditEnvironment);
        }
        else
        {
            AnsiConsole.MarkupLine("[green]Starting Camel MCP Server in stdio mode...[/]");
            await CamelMCPServer.RunStdioAsync(auditEnvironment);
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
