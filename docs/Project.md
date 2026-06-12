# About

Camel is designed to 'lower' DFIR analysis by AI from thinking using natural language skills over low-level tools, to thinking using code generation over specialized operations and workflows and machine learning routines
that codify existing DFIR analyst knowledge
. This lowering
significantly reduces the time AI agents spend

# Advantages

There are several advantages of implementing a high-level SDK for forensic tool operations in a modern statically-typed language like C# that can be accessed in a constrain:

* Deterministic output: High-level code operations are repeatable at a high level allowing the same sequence of forensic tool commands to be replayed everytime an operation is called.
* Parallel execution: Workflow steps without dependencies can execute in parallel, significantly reducing the run times for analysis. In JavaScript all workflow steps can be awaited
* Dedicated ML routines for data-intensive tasks: Tasks like timeline analysus