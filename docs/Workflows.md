# Camel Workflows

`Camel.Workflows` codifies established DFIR procedures into high-level, reusable operations
built on top of the strongly-typed SIFT tool API in [`Camel.Toolkits`](ToolkitCoverage.md).
Where a toolkit method wraps a single forensic tool, a *workflow* orchestrates many toolkit
calls — running tools, mounting images, parsing artifacts, correlating across sources, and
applying detection heuristics — to answer an investigative question in one call.

## Design

Every workflow class derives from the base `Workflow` (see
[Workflow.cs](../src/Camel.Workflows/Workflow.cs)), which:

- Takes a single `CamelToolkitsApi` and exposes the individual toolkits (DiskAnalysis,
  MemoryAnalysis, WindowsAnalysis, Yara, Timeline, LinuxAnalysis, PacketAnalysis) to the
  derived workflow methods.
- Provides `AuditScope()`, opened at the top of each public workflow method, so every tool
  execution underneath is attributed in the per-case audit trail as
  `Workflow → WorkflowOperation → Toolkit → Operation → command`.

The **public workflow API** is the set of public instance methods that return
`Task<WorkflowResult<T>>`. `WorkflowResult<T>` is a uniform success/failure envelope carrying
either a strongly-typed report `Result` or an explanatory failure `Message`, so callers (the
code-mode agent's JS engine, the CLI, and tests) handle every workflow the same way. Each
workflow's report type (`...Report`) is defined alongside it in the matching `*WorkflowModels.cs`.

Larger workflow classes are split across partial-class files by theme (e.g.
`WindowsAnalysisWorkflow.Email.cs`, `WindowsAnalysisWorkflow.Browser.cs`,
`DiskAnalysisWorkflow.BitLocker.cs`).

## Public workflow API surface

Count of public instance methods returning `Task<WorkflowResult<T>>`, grouped by class:

| Workflow class | Methods |
|---|---|
| WindowsAnalysisWorkflow | 21 |
| DiskAnalysisWorkflow | 15 |
| MemoryAnalysisWorkflow | 14 |
| TimelineAnalysisWorkflow | 10 |
| LinuxAnalysisWorkflow | 10 |
| PacketAnalysisWorkflow | 8 |
| AntiForensicsAnalysisWorkflow | 2 |
| WebServerWorkflow | 2 |
| **Total** | **82** |

Notes:

- `WindowsAnalysisWorkflow` includes two overloads of `ValidateProcessTreeAsync`, counted as
  two distinct methods. Collapsing the overload makes the class total 20 and the grand total 81.
- All methods are non-`static` instance methods returning the generic `WorkflowResult<T>`
  envelope; there is no non-generic `WorkflowResult`.
- Per-class methods are spread across partial-class files: WindowsAnalysisWorkflow (5 files),
  LinuxAnalysisWorkflow (8), PacketAnalysisWorkflow (5), DiskAnalysisWorkflow (3).
