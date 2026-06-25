namespace Camel.DFIR.Toolkits;
using Camel.Toolkits;

using Microsoft.Extensions.Configuration;

using Camel.Environments;
using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;

public class YaraToolkit : Toolkit
{
    public YaraToolkit(AuditEnvironment auditEnvironment, IConfigurationRoot? config = null) : base("Yara", auditEnvironment, config) { }

    /// <summary>
    /// Workstation install directory for the bundled Yara-Rules community rules pack
    /// (<see href="https://github.com/Yara-Rules/rules"/>). Populated lazily by <see cref="InstallMissingTools"/>
    /// and structured per rule category: <c>malware/</c>, <c>cve_rules/</c>, <c>webshells/</c>, etc. Workflows
    /// pass a category subdirectory (or the master <c>index.yar</c>) to <see cref="ScanAsync"/> /
    /// <c>ScanMemoryWithYaraAsync</c>.
    /// </summary>
    public const string RulesRepoPath = "/opt/yara-rules";

    /// <summary>
    /// Installs the <c>yara</c> apt package (providing both the <c>yara</c> scanner and <c>yarac</c>
    /// compiler) when the latest SIFT image omits it, plus the Yara-Rules community rules pack at
    /// <see cref="RulesRepoPath"/> — a curated reference set spanning malware families, exploit kits,
    /// webshells, CVEs, and packers, suitable as default IOC rules for the YARA workflows. No-op for either
    /// when it is already present.
    /// </summary>
    protected override void InstallMissingTools()
    {
        InstallAptPackage("yara", "/usr/bin/yara");
        // index.yar is the top-level aggregator the repo ships; if it's there the pack is installed.
        InstallGithubRepoZip("yara-rules",
            "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
            RulesRepoPath, $"{RulesRepoPath}/index.yar");
    }

    /// <summary>
    /// Scans <paramref name="scanPath"/> (a file or, with <c>options.Recurse</c>, a directory) using the
    /// YARA rules in <paramref name="rules"/>. <paramref name="options"/> maps to the yara command flags
    /// (recursion, tags/meta/strings output, timeout, threads, compiled rules, etc.). Returns one
    /// <see cref="YaraMatch"/> per rule/file hit.
    /// </summary>
    public async Task<YaraMatch[]?> ScanAsync(string rules, string scanPath, YaraOptions? options = null) =>
        await ExecuteToolTextAsync("Scan", (options?.ToArgs() ?? "") + Q(rules) + " " + Q(scanPath))
            is { } o ? YaraMatch.ParseAll(o) : null;

    /// <summary>
    /// Compiles the YARA rules in <paramref name="rules"/> to the binary rules file
    /// <paramref name="output"/> on the workstation (for faster reuse with <c>Scan(..., compiled: true)</c>).
    /// Returns true on success.
    /// </summary>
    public async Task<bool> CompileAsync(string rules, string output)
    {
        auditEnvironment.FailIfEvidenceSpoliationRisk(output);   // never write compiled rules over evidence
        return await ExecuteToolTextAsync("Compile", Q(rules) + " " + Q(output)) is not null;
    }

    public override string[] ToolList { get; } = ["Scan", "Compile"];

    // Single-quote a path so spaces survive the shell.
    private static string Q(string path) => $"'{path}'";
}
