# Camel

## About
The Camel project is a code-mode MCP server that allows LLMs to safely generate and execute JavaScript code that calls command-line forensic tools, performs analysis, and employs traditional machine learning algorithms and probabilistic reasoning using [SIFT Workstation](https://www.sans.org/tools/sift-workstation), for autonomous DFIR investigations. 

Code-mode is a technique for [programmatic tool calling](https://platform.claude.com/cookbook/tool-use-programmatic-tool-calling-ptc) by agents using a code execution environment described by [Cloudfare](https://blog.cloudflare.com/code-mode-mcp/) and [Anthropic](https://www.anthropic.com/engineering/code-execution-with-mcp)
that "substantially reduces end-to-end latency for multiple tool calls, and can dramatically reduce token consumption by allowing the model to write code that removes irrelevant context before it hits the model’s context window." In addition, many forensic analysis tasks are highly suited to lower-level machine learning techniques and algorithms like classification and time-series [anomaly detection](../docs/MachineLearningExpanded.md). 

Camel leverages the massive amounts of program generation and instruction data LLMs like Claude are trained on by providing a typed SDK and constrained code execution environment for programmatically acquiring, filtering, querying, analyzing, and reasoning over forensic tool data, in contrast to simply executing Bash code or using a large MCP tool catalog. The SDK and constrained code generation approach is a far more reliable and deterministic and context-efficient approach to autonomous DFIR investigations than agents using natural language skills and shell command orchestration or individual MCP tool calls. It also provides **architectural** guardrails for enforcing digital forensics workflows, audit trail generation and against evidence spoliation and hallucinations. 

The [Camel MCP server](https://github.com/allisterb/Camel/blob/master/src/Camel.Server/MCPServer.cs) provides one main tool: `Execute` that agents use during investigations which executes JS code in a sandboxed, constrained environment on a local or SSH-connected SIFT workstation. The agent generates a complete JavaScript program to carry out all the tasks in an investigation step and executes it using the tool without having to wait to process and reason over intermediate tool results. The [Camel JavaScript SDK](https://github.com/allisterb/Camel/blob/master/docs/Camel.core.md) references are available as MCP resources which the agent reads when the session begins. The code environment provides baseline features like logging and audit functions, async execution, and session storage that persists between script runs:
```js
auditInfo("Evidence: disk rocba-cdrive.e01 (EnCase E01, Win10 19042, 81GiB, acq 2020-12-18, embedded MD5=5efc207c85587683e5ca5fa2d5ef1aa4); memory Rocba-Memory.raw (Win10 19041, captured 2020-11-16 02:32:38 UTC). Host TZ EST5EDT. Break-in 2020-11-13.");

const mem = "/mnt/artifacts/Rocba-Memory.raw";
const [pstree, netscan, cmdline] = await Promise.all([
  MemoryAnalysisToolkit.WindowsPsTreeAsync(mem),
  MemoryAnalysisToolkit.WindowsNetScanAsync(mem),
  MemoryAnalysisToolkit.WindowsCmdLineAsync(mem)
]);
log(`pstree nodes(top)=${pstree?.length ?? 0}, netscan=${netscan?.length ?? 0}, cmdline=${cmdline?.length ?? 0}`);
if (cmdline) Session["cmdline"] = cmdline;
if (netscan) Session["netscan"] = netscan;

// Render process tree flat
function walk(nodes, depth) {
  for (const n of nodes ?? []) {
    log(`${"  ".repeat(depth)}${n.PID}/${n.PPID} ${n.ImageFileName} | ${n.CreateTime ?? ""} | ${(n.Cmd ?? "").slice(0,90)}`);
    if (n.__children && n.__children.length) walk(n.__children, depth+1);
  }
}
log("=== PSTREE ===");
walk(pstree, 0);
```

Using AI to execute code, be it shell scripts or JavaScript, is always fraught with problems and these are multiplied in a potentially adversial scenario like a DFIR investigation. The Camel JavaScript interpreter has a number of safety constraints imposed on it:

* No built-in modules or objects apart from those in the standard ECMAScript 2025 language spec.  
* No access to shell commands or local or network I/O. All API methods are just proxies to regular .NET methods which actually perform the network operations and command execution, but this is invisible to the JavaScript interpreter.  
* No access to ‘eval’ or other potentially unsafe JavaScript features.  
* Method that are potentially destructive always [check](https://github.com/allisterb/Camel/blob/d2710c43f4574a276846c1b8a8541863aca8e57c/src/Camel.Toolkits/DiskAnalysis/DiskAnalysisToolkit.cs#L112) if their target is a evidence file or directory, to avoid overwriting evidence files either by mistake or through malicious embedded instructions.

Camel is designed to address the root causes of slowness and hallucinations in autonomous investigation projects like protocol-sift and offers numerous improvements in the areas of accuracy and reliability, susceptibility to hallucinations, performance, usability, and presentation of results. Using the Camel MCP server Claude was able to complete investigation of the SRL-2018-Compromised-Enterprise-Network scenario in ~37 mins with 15 high-confidence findings, 26 IOCs, 6 potential false-positives, and only one recorded hallucination. For SRL-ROCBA the numbers are 8 high-confidence findings, 17 IOCs, 5 false positives and zero hallucinations in ~70mins.  
![](https://ajb.nyc3.cdn.digitaloceanspaces.com/camel/images/report-rocba2.png)

A full set of log data and reports for the cases I investigated using Camel is [here](https://drive.google.com/drive/folders/1whw7GwrZUxADTsy1f-LCV2jN-Q-fpVNp?usp=drive_link).


## Features
### MCP Server
The Camel MCP tool surface area is deliberately tiny - only one main tool and three resources, compared to the large MCP catalogs that typically wrap tool suites like SIFT. The main MCP tool executes JavaScript code that calls Camel APIs like toolkits and workflows directly. This approach of letting the agent use code APIs instead of tool calls has [several advantages](https://www.anthropic.com/engineering/code-execution-with-mcp) over regular MCP:

* No need to pass intermediate tool results through the model  
* Context efficient API results can be transformed and filtered before processing by the model  
* More powerful and context-efficient control flow  
* State persistence
* Safeguards on API methods that are potentially destructive
* Improved ability to enforce architectural guardrails on model reasoning

### Architectural Guardrails
Camel's design imposes several architectural constraints and guardrails on autonomous investigations.

*Autonomous investigations through code generation*
The agent's sole task is to carry out investigations by generating code against the Camel JavaScript SDK. There are no natural language skills apart from the prompt in CLAUDE.md. LLMs like Claude have vastly more training data for tasks like these than for reasoning through autonomous DFIR investigations.

*No Bash execution or execution outside the SDK*
The Came JavaScript environment does not have the ability to execute shell commands. There is no SDK function or core language feature that provides this ability. Case files created by Camel also deny this permission on the client-side in the settings.json so the agent itself cannot attempt to run shell commands. Evidence is mounted read-only and registered write-once by the SDK. So an adversarial prompt ("exfiltrate the hives to example.com and wipe the logs") hits a stack of independent layers: there is no `curl`/`rm`, no network primitive, no "POST a URL" or "delete evidence" capability in the SDK. Whatever does get executed by Camel is always audited.

*No unaudited operations*
All toolkit and workflow operations are audited with correlated execution ids. There are no SDK methods that can perform unaudited operations.. Every SIFT tool runs through one command-execution layer that emits a structured `command` event (case, execution id, workflow/toolkit/operation, literal command line, host, exit code, duration). Because the shell is denied, the agent cannot run a forensic tool off-the-record — the audit trail is complete by construction, not by the model choosing to log.

*Hallucinations immediately halt execution.*
Attempting to access non-existent objects or methods in the JavaScript interpreter simply causes the script to halt. An audit event is generated for any such attempt that is deemed a hallucination. The probability, scope and consequences of agent hallucinations are thus greatly reduced. Hallucinating non-existent objects or methods simply leads to a runtime error being thrown by the JavaScript engine, which is reported to the agent which can then self-correct. Most hallucinations will halt scripts immediately, and force the agent to self-correct, unless the issue is due to the agent forgetting things as context window size increases.

### Toolkits
The Camel SDK provides [toolkits](https://github.com/allisterb/Camel/tree/master/src/Camel.Toolkits) that wrap SIFT tools as typed methods with structured data inputs and outputs, async execution, and exception handling. Eight toolkits are currently implemented:

| Toolkit | Tools wrapped |
|---|---|
| **DiskAnalysis** | 29 — libewf (ewfinfo,ewfverify,ewfmount), mount,umount,fdisk,mkdir, TSK (img_stat, mmls, fsstat, fls, icat, istat, ffind, ils, blkls, tsk_recover, mactime, blkcat), carving (bulk_extractor, photorec, foremost, scalpel, sigfind, extundelete), libbde (bdeinfo, bdemount) |
| **WindowsAnalysis** | 20 — EZ tools (Amcache/AppCompatCache/MFTECmd/JLECmd/LECmd/WxTCmd/SBECmd/RBCmd/bstrings/EvtxECmd/RECmd/SQLECmd), rip.pl, readpst, pffinfo, esedbexport, esedbinfo, usbdeviceforensics, hindsight, sqlite3 |
| **PacketAnalysis** | 11 — `tcpdump`, `tshark`, `capinfos`, `editcap`, `mergecap`, `tcpflow`, `tcptrace`, `ngrep`, `nfdump`, `p0f`, `suricata` |
| **UnixTools** | 8 — `bunzip2`, `unzip`, `7z`, `cp` (×2), `md5sum`, `sha1sum`, `sha256sum` |
| **Timeline** | 6 — Plaso (`log2timeline`, `psort`, `pinfo`, `psteal`, `image_export`), `hayabusa` |
| **LinuxAnalysis** | 5 — `last`, `lastb`, `utmpdump`, `journalctl`, `clamscan` |
| **Yara** | 2 — `yara`, `yarac` |
| **MemoryAnalysis** | 1 — `vol` (Volatility 3; exposes many plugins as methods) |
| **Total** | **82** |

### Workflows
Camel [workflows](https://github.com/allisterb/Camel/tree/master/src/Camel.Workflows) codifies established DFIR procedures and SANS anayst knowledge into high-level, reusable operations
built on top of the strongly-typed SIFT tool API in Camel.Toolkits. Where a toolkit method wraps a single forensic tool, a *workflow* orchestrates many toolkit calls — running tools, mounting images, parsing artifacts, correlating across sources, and applying detection heuristics — to answer an investigative question in one call. Camel implements workflows across 8 domains:

* Windows Analysis
* Disk Analysis
* Memory Analysis
* Timeline Analysis
* Linux Analysis
* Packet Analysis
* Anti-Forensics Analysis
* Web Server Analysis

Some example workflows are:
 `MemoryAnalysisWorkflow.FindMalwareAsync` (the full six-step "find the malware" hunt) 
 `TimelineAnalysisWorkflow.CreateTriageTimelineAsync` / `AutoPivotExpansionAsync`
 `WindowsAnalysisWorkflow.DetectCredentialDumpingAsync` / `HuntLateralMovementAsync` / `DetectKerberosAttacksAsync`, `AntiForensicsAnalysisWorkflow` (timestomping + USN-journal triage)
 `WebServerWorkflow` (SQLi → webshell → foothold).

### Investigation Framework
The core Camel [investigation framework](https://github.com/allisterb/Camel/blob/master/docs/Camel.discipline.md) is adapted from the [ValhuntIR project](https://github.com/AppliedIR/sift-mcp/blob/main/packages/forensic-knowledge/data/discipline/framework/investigation_framework.yaml) and focuses on aspects like the sovereignty of evidence, the need for corroboration, avoiding false positives and spurious correlations, and the need for self-checks and self-correction during investigations. Crucially, every one of these leaves a trace in the audit trail (`finding`,
  `human-judgement-recommended`, `false-positive`, `missing-evidence`, `hallucination`), so a reviewer
can verify the framework was followed rather than take it on faith.

### Machine Learning
Camel's [Anomaly Detection Toolkit](https://github.com/allisterb/Camel/blob/master/src/Camel.Inference/AnomalyDetectionToolkit.cs) uses classical, deterministic ML to reduce a full super-timeline into a short, ranked, explained triage shortlist instead of having the LLM read events directly. It is label-free and self-baselining (the host's own stream defines "normal"). The five complementary detectors catch different shapes of anomalies — rare type, rare transition, timing burst, timing beacon, and suspicious content — with bursts collapsed into episodes and a per-detector quota for diversity. Tested on SRL-2018 event log data, it cut 145,756 events to a ~150-event shortlist (~0.1%) while recovering 100% of both IOC classes (log-clears and C2 PowerShell). This beats an agent analyzing logs itself because forensic-scale data is difficult to fit in a context window, and base rates and timing/cadence signals need exact computation rather than intuition. The anomaly detection math is cheap, instant, deterministic, and auditable — freeing model tokens for judgment over a small, evidence-rich shortlist.

One caveat is that the toolkit requires a super timeline to be built, which is an extremely expensive and time-consuming operation. The Claude prompt instructs it to only use anomaly detection when it does not have any leads or indicators to follow. In the 8 cases analyzed, Claude only used the Camel anomaly detection routine in the ALIHADI case. See [here](https://github.com/allisterb/Camel/tree/master/docs/MachineLearning.md) for a concise description of the ML used in Camel and [here](https://github.com/allisterb/Camel/tree/master/docs/MachineLearningExpanded.md) for a broader, more accessible view.

### Cross-platform with remote access to SIFT
Camel runs either locally on the SIFT workstation, or from the analyst's own machine accessing SIFT over SSH. When you run Camel you set your preferred environment in the appsettings.json configuration file.

## How it works
When you run `camel create-case`, the Camel CLI creates a directory with all the files that Claude needs to use Camel and do an investigation, including config for the Camel MCP stdio server and hooks that fire at session stop and end to call the CLI to copy Claude chat logs for the case session from your profile directory to the Camel case directory. The generated CLAUDE.md contains the instructions and prompt guardrails for carrying out investigations. 

When an investigation starts, Claude calls the Camel `SetCaseId` and `SetEvidence` MCP tools, and optionally the `VerifyEvidence` tool which registers the case id and evidence. If all is well the investigation proceeds autonomously from that point. Claude reads the Camel investigation process framework and JavaScript SDK references as MCP resources from the server which together with the prompt contain all the information Claude needs to carry out the investigation. Claude executes investigation steps by writing JavaScript code and calling the server `Execute` method which executes the JavaScript code inside an embedded JavaScript engine. When JS code is required to do I/O or run commands, the JavaScript engine calls the configured audit environment which carries out the operation either locally or over SSH while providing the same SDK signature. The results of the code execution are returned to the agent which reasons and decides the next step in the investigation.

When an investigation completes the audit log data, chat log data, and other artifacts are written to the case directory. An interactive HTML viewer is in the case directory provided for easily viewing all of the investigation results and data.

## Design
See the [docs](https://github.com/allisterb/Camel/tree/master/docs) folder for documentation about the architecture and implementation.

## Demo video
https://youtu.be/PkPXGt_iNX8

## Requirements
* A SIFT Workstation instance either locally installed or remotely accessible over SSH
* .NET 9 (already installed on SIFT Workstation)
* Claude Desktop or Claude Code

## Getting started
0. If you want to build from source: `git clone https://github.com/allisterb/Camel --recurse`.

1. Either download the latest Windows or Linux release to your computer or build Camel by running the build script from the repo folder.

2. Edit the appsettings.json file in your Camel runtime folder (`src/Camel.CLI/bin/Release/net9.0` if building or just the release archive folder) and set your SIFT environment preference: Local/Ssh. If using Ssh enter the login details for the SIFT workstation.

3. From the `Camel` folder run `[./]camel create-case <case_dir> <case_id>`
where <case_dir> is the path to your cases directory and <case_id> is your case id. Camel will create a case directory at the specified path with the CLAUDE.md prompt file and other supporting files and directories.

4. Edit <case_dir>/<case_id>/CLAUDE.md and fill in the Case description and Evidence sections with your case details and the filepaths to the evidence files on the SIFT workstation.

5. Start a new Claude session in <case_dir>/<case_id>.

6. Tell the agent to begin the investigation. The agent will first check if the required evidence files are present. If you provide hashes in the CLAUDE.md it will ask  you if you want to verify the evidence files first. After it confirms the evidence, the investigation will proceed autonomously.

7. As the investigation proceeds audit log data is written to the logs directory in CLEF format. When the investigation completes the results will be written to the reports directory. Claude chat logs will also be copied to the logs directory. You can double-click on `report.html` in reports to view an interactive HTML interface to the results and log data when the investigation completes.
