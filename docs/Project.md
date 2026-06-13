# About



Camel is designed to 'lower' DFIR analysis by AI from thinking using natural language skills over low-level tools, to thinking using code generation over specialized operations and workflows and machine learning routines
that codify existing DFIR analyst knowledge
. This lowering
significantly reduces the time AI agents spend

# Advantages

There are several advantages of implementing a high-level SDK for forensic tool operations in a modern statically-typed language like C# that can be accessed in a constrain:

* Reduced hallucination. Using Camel the primary task of the agent is code generation against a a typed, fully documented SDK. LLMs are typically trained on huge amounts of code-generation data
* fpr the task of learning how to implement programs given natural language descriptions. The Camel MCP tool surface area is deliberately tiny - only
* one tool and two resources, compared to the large toolsets typically shipped over large APIs. The probabilty, scope and consequences of hallucinations are thus greatly reduced. Hallucinating non-existent objects or methods or properties simply leads
* to a runtime error by the JavaScript engine. These errors are reported to the agent which can then self-correct. Hallucinations halt scripts immediately, the script does not
* continue after attempting to access a non-existent JavaScript element.


* 
* Deterministic execution: Forensic analysis operations implemented as Camel are repeatable at a high level allowing the same sequence of forensic tool commands to be replayed everytime an operation is called.
* Parallel execution: Workflow steps without dependencies can execute in parallel, significantly reducing the run times for analysis. In Camel JavaScript all workflow steps can be awaited using promises.
* Dedicated ML routines for data-intensive tasks: Tasks like timeline analysus


# Execution mode
Camel is a cross-platform .NET application that can execute either directly on the Linux-based SIFT workstation, or on a Windows or Linux machine that can connect to a SIFT workstation
over SSH. Camel runs and stores its evidence on the analyst machine only.

