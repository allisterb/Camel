# Camel vs. Protocol SIFT

Camel is designed as a context-efficient alternative to the high-level agentic reasoning over MCP
tool outputs employed by [Protocol SIFT](https://github.com/teamdfir/protocol-sift) and similar
DFIR AI-automation projects. Protocol SIFT drives DFIR through Claude Code *skills* that invoke
SIFT command-line tools (via Bash), with the agent reasoning over the raw tool output in its
context window. Camel moves that work below the model into a typed, sandboxed, audited
code-execution layer.

| Dimension | Protocol SIFT | Camel | How Camel improves |
|---|---|---|---|
| **Tool-calling model** | Agent invokes SIFT CLIs one at a time (Bash / skill-driven), each as a separate tool call | Code-mode: agent writes JavaScript that calls a typed SDK; many tool operations run inside one execution | Collapses dozens of round-trips into a single program; the model orchestrates, the engine executes |
| **Data flow / context cost** | Raw tool output returns into the context window every call | Filtering, parsing, correlation, and reduction happen *in-engine*; only distilled results return | Large outputs (a 245 MB EVTX, a 145k-event timeline) never hit the context window — major token savings |
| **Latency / round-trips** | One model round-trip per tool; largely sequential | Batches calls per script and parallelizes independent ops (`Task.WhenAll`) | Fewer model turns and concurrent tool execution → lower end-to-end latency |
| **Tool interface** | Free-form CLI strings; the LLM parses unstructured text output | Strongly-typed SDK methods returning typed models | Eliminates a whole class of brittle, token-heavy text-parsing errors |
| **Forensic procedures** | Encoded as skill *documentation* the LLM reads and follows | Codified as **82 executable workflow methods** returning a uniform `WorkflowResult<T>` | Procedures run as tested code, not prose the model must re-interpret each run |
| **Heavy analysis / ML** | LLM performs classification / anomaly reasoning itself, in-context | Classical-ML **AnomalyDetectionToolkit** does the quantitative reduction deterministically | Catches base-rate, timing, and cadence signals an LLM can't compute by eye — and frees tokens for judgment |
| **Audit trail** | Relies on the Claude Code transcript | Per-case CLEF audit log; every command attributed `Workflow → Operation → command` with execution IDs | Court-defensible chain of custody by construction, not reconstructed from a chat log |
| **Evidence integrity** | Convention / skill guidance | Write-once evidence registration + spoliation guard + EWF (`ewfverify`) integrity check enforced at the environment layer | Spoliation protection is architectural — generated code cannot bypass it |
| **Execution safety** | Agent runs arbitrary Bash on the host | Constrained Jint JS engine exposing only the SDK, with timeouts, cancellation, and concurrency caps | Sandboxed execution surface instead of unrestricted shell access |
| **Deployment** | Runs on the SIFT workstation (local) | Same code runs local **or** against a remote SIFT over SSH (audit environments) | Analyst's machine can be separate from the evidence host without code changes |
| **Reproducibility** | LLM-mediated parsing/analysis is stochastic | Deterministic SDK + deterministic ML | Same evidence → same findings → same scores |

**Summary:** Protocol SIFT has the *agent* drive CLI tools and reason over their raw text; Camel
moves that work below the model into a typed, sandboxed, audited code-execution layer — so the LLM
spends its tokens on forensic *judgment* rather than on bulk data wrangling.

## Related documentation

- [Audit Environments](AuditEnvironments.md) — the local/remote I/O layer beneath the toolkits
- [Toolkit Coverage](ToolkitCoverage.md) — the SIFT tools wrapped by each toolkit
- [Workflows](Workflows.md) — the executable workflow API surface
- [Machine Learning](MachineLearning.md) — the AnomalyDetectionToolkit and why it beats in-context log analysis
