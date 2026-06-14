# About

Camel is designed to 'lower' DFIR analysis by AI from thinking using natural language skills over tools generating plain-text delimited data, to thinking using code generation over specialized operations and workflows and machine learning routines
that codify existing DFIR analyst knowledge and consume and produce structured data.
This lowering significantly reduces the time AI agents must spend in autonomous investigations and the accuracy and depth of their findings.

Toolsets based on large APIs lik can consume a large number of input tokens before execution even begins. There are also limited ways to transform and filter the results of MCP tool calls before passing them through the model, or perform operations like aggregation, joins across multiple data sources, or select and extract specific fields, all of which increases the input token requirements. AI agents in general have far more training data for correct program generation in languages like JavaScript than for reasoning over tool usage for system administration tasks. As the context window size grows the possibility for the model performing system administration tasks to make mistakes using the API or misunderstand the user’s intentions or the consequences of an operation increases. 
# Advantages

# Security

Using AI to execute code is always fraught with problems and in a potentially adversarial situation like digital forensic investigations, such concerns are multiplied

the [Donna JavaScript interpreter](https://github.com/allisterb/netdo/blob/master/src/NetDo.Cli/JSInterp.cs) has a number of safety constraints imposed on it:

* No built-in modules or objects apart from those in the standard ECMAScript 2015 language spec.  
* No direct access to shell commands or local or network I/O. All Camel SDK methods are just proxies to regular .NET methods which actually perform the network operations and command-line invocations, but this is invisible to the JavaScript interpreter.  
* No access to ‘eval’ or other potentially unsafe JavaScript features.  
* Digital Ocean API methods that cause configuration changes require confirmation by the user.  

This approach of allowing the agent to use code APIs instead of using direct tool calls has [several advantages](https://www.anthropic.com/engineering/code-execution-with-mcp) over regular MCP:

* No large tool definitions that overload the context window  
* No need to pass intermediate tool results through the model  
* Context efficient API results can be transformed and filtered before processing by the model  
* More powerful and context-efficient control flow  
* Safeguards on API methods that are potentially destructive

* 
There are several advantages of implementing a high-level SDK for forensic tool operations in a modern statically-typed language like C# that can be accessed in a constrain:

* Reduced hallucination compared to using natural language skills. Using Camel the primary task of the agent is code generation against a a typed, fully documented SDK. LLMs like Claude are typically trained on huge amounts of data
* fpr the task of learning how to correctly implement programs given natural language descriptions. The Camel MCP tool surface area is deliberately tiny - only
* one tool and two resources, compared to the large MCP catalogs that typically wrap tool suites like SWIFT. The probabilty, scope and consequences of agent hallucinations are thus greatly reduced. Hallucinating non-existent objects or methods or properties simply leads
* to a runtime error thrown by the JavaScript engine. These errors are reported to the agent which can then self-correct. Hallucinations halt scripts immediately, the script cannot
* continue after attempting to access a non-existent JavaScript object or method.

* Reduced model round trips and context window sizes. Every tool call must be processed by the model and reasoned over. Using code generation, tool calls can be wired together and filtered and queried and tested before the output ever touches the modell.

* Self-correct

```
Used camel: Execute
script: 
const mem = Session["paths"].mem;
const ps = await MemoryAnalysisToolkit.WindowsPsListAsync(mem);
log("pslist count: " + (ps?.length ?? "null"));
if (ps) {
  // sort by create time, show name/pid/ppid/create
  const rows = ps.map(p=>[p.CreateTime||"", p.PID, p.PPID, p.ImageFileName, p.SessionId]).sort((a,b)=> (a[0]<b[0]?-1:1));
  // Flag potential exfil/attacker tooling
  const susp = /rclone|winscp|ftp|curl|wget|7z|rar|psexec|mimikatz|nc\.exe|ncat|powershell|cmd\.exe|mega|dropbox|filezilla|putty|robocopy|bits|certutil|scp/i;
  log("\n=== processes of interest (exfil/admin/LOLBin) ===");
  for (const r of rows) if (susp.test(r[3])) log(`${r[0]} pid=${r[1]} ppid=${r[2]} ${r[3]} sess=${r[4]}`);
  log("\n=== cloud-sync / collaboration clients ===");
  for (const r of rows) if (/onedrive|googledrive|gdrive|icloud|dropbox|teams|slack|outlook/i.test(r[3])) log(`${r[0]} pid=${r[1]} ppid=${r[2]} ${r[3]} sess=${r[4]}`);
  log("\n=== full process list (name pid ppid create) ===");
  for (const r of rows) log(`${r[3]}\t${r[1]}\t${r[2]}\t${r[0]}`);
}
Error: result (389,752 characters) exceeds maximum allowed tokens. Output has been saved to C:\Users\Allister\.claude\projects\C--Projects-Camel-cases-SFC-ROCBA\c4f27618-2be8-4447-a540-da59cc1d66cb\tool-results\mcp-camel-Execute-1781377870456.txt.
Format: JSON array with schema: [{type: string, text: string}]
Use offset and limit parameters to read specific portions of the file, search within it for specific content, and jq to make structured queries.
REQUIREMENTS FOR SUMMARIZATION/ANALYSIS/REVIEW:
- You MUST read the content from the file at C:\Users\Allister\.claude\projects\C--Projects-Camel-cases-SFC-ROCBA\c4f27618-2be8-4447-a540-da59cc1d66cb\tool-results\mcp-camel-Execute-1781377870456.txt in sequential chunks until 100% of the content has been read.
- If you receive truncation warnings when reading the file, reduce the chunk size until you have read 100% of the content without truncation.
- Before producing ANY summary or analysis, you MUST explicitly describe what portion of the content you have read. ***If you did not read the entire content, you MUST explicitly state this.***
- If after a few attempts you cannot read the file (file not found, lines too long for Read's offset/limit, no shell access), STOP retrying. Summarize what you were able to read, explicitly state which portion you could not read and why, and proceed.
```

* Deterministic execution: Forensic analysis operations implemented as Camel are repeatable at a high level allowing the same sequence of forensic tool commands to be replayed everytime an operation is called.

* Parallel execution: Workflow steps without dependencies can execute in parallel, significantly reducing the run times for analysis. In Camel JavaScript all workflow steps can be awaited using promises.

* Dedicated ML routines for data-intensive tasks: Tasks like timeline analysis typ



A typicat Camel.Execute tool call looks like this:

```js

# Execution mode
Camel is a cross-platform .NET application that can execute either directly on the Linux-based SIFT workstation, or on a Windows or Linux machine that can connect to a SIFT workstation
over SSH. Camel runs and stores its evidence on the analyst machine only.

## How we built it
## Project design and architecture
Camel is written in .NET and C#. It is designed to run either installed locally on the SIFT Workstation, or on a separate machine that can access a SIFT workstation over SSH. There are 7 main projects:
- Camel.Runtime: provides global base types and features like logging for all other projects.
- Camel.EnvironmentsL provides different **audit environments** that represent the local or remote machine SIFT workstation is running on. An audit environment allows common I/O operations like running commands and reading files to be abstracted so
the same code works locally or remotely over SSH.
- Camel.ToolkitsL provides a strongly-typed, asynchronous API for the SIFT command-line tools. 
- Camel.Workflows: codifies existing forensic tool knowledge into high-level repeatable workflows utilizing the SIFT tools API.
- Camel.Server: provides the constrained JavaScript execution environment, the MCP server implementation, and the audit trail implementation for evidence gathering autonomous case investigations.
- Camel.Training at src/Camel.Training For training/evaluating ML over forensic timelines and generating synthetic data: the embedding/novelty stack (TimelineNoveltyBaseline, ONNX embedders via Camel.Search, renderers), the eval harnesses (AnomalyDetectionEval metrics, DatasetEvaluator), SyntheticIntrusion, and the CSV/dataset loaders. References Camel.Inference. NOTE: Camel.Search is for the JS-SDK vector search only and must NOT be a dependency of any toolkit/Inference/Server — only Camel.Training (the experiment project) references it.
- Camel.Inference at src/Camel.Inference The lean runtime/inference ML core (no ONNX/Search dependency): the canonical event model (CanonicalEvent, EventCanonicalizer, ContentSignals, NoiseFilters), windowing, the (event_id, Δt) anomaly detectors + ensemble (EventDetectors), and the agent-facing AnomalyDetectionToolkit triage façade. Exposed to the code-mode agent's JS engine as `anomaly`.
- Camel.CLI at src/Camel.CLI provides the main interface for launching the Camel MCP server and other programs.

## Project milestones

- Implement local and SSH audit environments to be used by toolkits and workflows
- Define all toolkits and tools to be implemented in Camel.Toolkits, and the models that represent their outputs.
- Define higher-level workflows to be implemented in Camel.Workflows.
- Implement anomaly detection techniques in Camel.Inference.
- Implement the code-mode MCP server and robust audit logs.
- Fork protocol-sift and modify it to use Camel (in progress)

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


