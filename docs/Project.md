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

* Deterministic execution: Forensic analysis operations implemented as Camel are repeatable at a high level allowing the same sequence of forensic tool commands to be replayed everytime an operation is called.

* Parallel execution: Workflow steps without dependencies can execute in parallel, significantly reducing the run times for analysis. In Camel JavaScript all workflow steps can be awaited using promises.

* Dedicated ML routines for data-intensive tasks: Tasks like timeline analysis typ


# Execution mode
Camel is a cross-platform .NET application that can execute either directly on the Linux-based SIFT workstation, or on a Windows or Linux machine that can connect to a SIFT workstation
over SSH. Camel runs and stores its evidence on the analyst machine only.

