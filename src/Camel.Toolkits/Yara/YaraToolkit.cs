namespace Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;

public class YaraToolkit : Toolkit
{
    public YaraToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("Yara", auditEnvironment, config) { }

    /// <summary>
    /// Installs the <c>yara</c> apt package (providing both the <c>yara</c> scanner and <c>yarac</c>
    /// compiler) when the latest SIFT image omits it. No-op when it is already present.
    /// </summary>
    protected override void InstallMissingTools()
    {
        InstallAptPackage("yara", "/usr/bin/yara");
    }

    /// <summary>
    /// Scans <paramref name="scanPath"/> (a file or, with <c>options.Recurse</c>, a directory) using the
    /// YARA rules in <paramref name="rules"/>. <paramref name="options"/> maps to the yara command flags
    /// (recursion, tags/meta/strings output, timeout, threads, compiled rules, etc.). Returns one
    /// <see cref="YaraMatch"/> per rule/file hit.
    /// </summary>
    public YaraMatch[]? Scan(string rules, string scanPath, YaraOptions? options = null) =>
        ExecuteToolText("Scan", (options?.ToArgs() ?? "") + Q(rules) + " " + Q(scanPath))
            is { } o ? YaraMatch.ParseAll(o) : null;

    /// <summary>
    /// Compiles the YARA rules in <paramref name="rules"/> to the binary rules file
    /// <paramref name="output"/> on the workstation (for faster reuse with <c>Scan(..., compiled: true)</c>).
    /// Returns true on success.
    /// </summary>
    public bool Compile(string rules, string output) =>
        ExecuteToolText("Compile", Q(rules) + " " + Q(output)) is not null;

    public override string[] ToolList { get; } = ["Scan", "Compile"];

    // Single-quote a path so spaces survive the shell.
    private static string Q(string path) => $"'{path}'";
}
