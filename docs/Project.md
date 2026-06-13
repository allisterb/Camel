# About

Camel is designed to 'lower' DFIR analysis by AI from thinking using natural language skills over plain-text delimited data, to thinking using code generation over specialized operations and workflows and machine learning routines
that codify existing DFIR analyst knowledge and consume and produce structured data.
This lowering significantly reduces the time AI agents must spend in autonomous investigations and the accuracy and depth of their findings.

# Advantages

There are several advantages of implementing a high-level SDK for forensic tool operations in a modern statically-typed language like C# that can be accessed in a constrain:

* Reduced hallucination compared to using natural language skills. Using Camel the primary task of the agent is code generation against a a typed, fully documented SDK. LLMs like Claude are typically trained on huge amounts of data
* fpr the task of learning how to correctly implement programs given natural language descriptions. The Camel MCP tool surface area is deliberately tiny - only
* one tool and two resources, compared to the large MCP tool catalogs that typically ship over larg. The probabilty, scope and consequences of agent hallucinations are thus greatly reduced. Hallucinating non-existent objects or methods or properties simply leads
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

