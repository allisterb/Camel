# About this project
The Camel project is a 'code-mode' MCP server that allows LLMs to safely generate and execute code that calls command-line forensic tools, performs processing, and employs classical machine learning algorithms and probabilistic reasoning using [SIFT workstation](https://www.sans.org/tools/sift-workstation) for automating DFIR. 
Camel is designed to leverage the massive amounts of program generation and analysis data LLMs are trained on and provides a typed SDK and constrained code execution environment for programmatically acquiring, filtering, querying, analyzing, and reasoning over forensic tool data, as a context-efficient alternative to high-level agentic reasoning over MCP tool outputs employed
by [Protocol SIFT](https://github.com/teamdfir/protocol-sift/tree/main) and other DFIR AI-automation projects. Code-mode is a technique for [programmatic tool calling](https://platform.claude.com/cookbook/tool-use-programmatic-tool-calling-ptc) by agents using a code execution environment described by [Cloudfare](https://blog.cloudflare.com/code-mode-mcp/) and [Anthropic](https://www.anthropic.com/engineering/code-execution-with-mcp)
that "substantially reduces end-to-end latency for multiple tool calls, and can dramatically reduce token consumption by allowing the model to write code that removes irrelevant context before it hits the model’s context window." In addition, many forensic analysis tasks are highly suited to lower-level machine learning techniques and algorithms like classification, decision trees, and time-series anomaly detection. 
Camel exposes an API for using implementations of these algorithms on forensic tool data as well as high-level workflows for acquiring and processing and analyzing forensic tool data, as an alternative to requiring the LLM to spend tokens and time on naively performing these low-level classification and analysis and inference tasks. Forensic analysis using Camel reduces to the task of generating the correct programs for ingesting, analyzing, and performing inference over forensic data using the provided API. 
Camel thus allows LLMs to efficiently and effectively reason over far higher-level forensic data features and measures than traditional DFIR AI-automation projects.

Camel is created as an entry into the [SANS Find Evil! AI Hackathon](https://findevil.devpost.com/).
	
## Project design and architecture
Camel is written in .NET and C#. It is designed to run either installed locally on the SIFT Workstation, or on a separate machine that can access a SIFT workstation over SSH. There are 7 main projects:
- Camel.Runtime at src/Camel.Runtime provides global base types and features like logging for all other projects.
- Camel.Environments at src/Camel.Runtime provides different **audit environments** that represent the local or remote machine SIFT workstation is running on. An audit environment allows common I/O operations like running commands and reading files to be abstracted so
the same code works locally or remotely over SSH.
- Camel.Toolkits at src/Camel.Runtime provides a strongly-typed, asynchronous API for the SIFT tools. 
- Camel.Workflows at src/Camel.Workflows codifies existing forensic tool knowledge into high-level workflows utilizing the SIFT tools API.
- Camel.Server at src/Camel.Server provides the constrained JavaScript execution engine and MCP server implementation.
- Camel.Training (planned) For training and testing machine learning models on forensic tool data, and for generating synthetic data for training and testing.
- Camel.Inference (planned) For performing inference using trained machine learning models on forensic tool data.
- Camel.CLI at src/Camel.CLI provides the main interface for launching the Camel MCP server and other programs.

## Project milestones

- Define all toolkits and tools to be implemented in Camel.Toolkits, and the models that represent their outputs.
- Define higher-level workflows to be implemented in Camel.Workflows (currently in progress).

## Project implementation

### Camel.Toolkits
Each toolkit implementation in Camel.Toolkits defines a collection of SIFT tools in  particular domain (e.g. memory analysis, timeline analysis, etc.) as methods on a class that inherits from the base Toolkit class. 
Each method should execute a SIFT tool and return a strongly-typed model representing the tool's output. A toolkit takes a single AuditEnvironment as a constructor parameter and uses it to perform any necessary I/O operations 
locally or remotely to execute the tool and acquire its output. Tools are defined in application settings files like in @tests\Camel.Tests.Toolkits\testappsettings.json.

When adding tools to a toolkit in the Camel.Toolkits project, follow the existing plan of defining a model type for the tool's output, adding the tool to the Toolkit.ToolList array,
and adding a method to the toolkit class that executes the tool and returns the output model, using the ExecuteTool method and any additional needed AuditEnvironment  I/O methods.
Add unit tests for the new tool method in the tests\Camel.Tests.Toolkits project, following the existing tests as examples. You can execute commands for tools on the SIFT
workstation as described in the Common Commands section below, and use the output to define the model properties for the tool's output model, and to implement the tool method itself.

### Camel.Workflows
Camel.Workflows codifies existing DFIR knowledge that uses tools in the different toolkits.

## Project coding instructions:
- When generating new C# code, please follow the existing coding style.
- All code should be compatible with .NET 9.0 and C# 13.0.
- Prefer new C# 13.0 features and syntax where applicable.
- Prefer functional programming paradigms and constructs where appropriate.
- Prefer concise code over more verbose constructs.
- Avoid modifying external library code located in the @ext directory. Changes should be limited to the code in the @src directory only whenever possible.

## Project coding style:
- Use the existing #regions in a file to organize class constructors, indexers, events, properties, methods, fields, and child types. When making changes try to keep different class element types like fields and methods in the specified regions.
- Use 4 spaces for indentation.
- Use camel-case for method and property names. Method and property names should begin with a capital letter.
- Use camel-case for class fields. Field names should begin with lower-case letters unless they are backing fields for properties which should begin with an underscore.

### Common Commands Setup
Read @tests\Camel.Tests.Environments\testappsettings.json for the SIFT workstation ssh_host, ssh_user, ssh_pw values to run commands against the remote SIFT workstation over SSH.
Read @tests\Camel.Tests.Toolkits\testappsettings.json for the SIFT workstation commands to run for each tool, which can be used as examples for running commands on the SIFT workstation to acquire output for implementing new tools.
Use / as the path-separator for file paths when building projects to avoid issues with escaping \ in file paths on Windows.

## Common Commands
```bash
bin\plink -ssh <sift_user>@<sift_host> -pw <sift_pw> <command> # Run a command on a remote SIFT workstation over SSH using plink
dotnet build <csproj_file>                                     # Build a project
dotnet test <csproj_file>                                      # Run unit tests in project.
dotnet run --project src\Camel.CLI\Camel.CLI.csproj            # Run Camel MCP server using HTTP transport
```