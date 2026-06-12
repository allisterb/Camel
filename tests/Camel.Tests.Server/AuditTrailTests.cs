namespace Camel.Tests.Server;

using System;
using System.IO;

using Camel;

/// <summary>
/// Tests the audit-trail infrastructure (criterion 5): a command audit event, enriched ambiently with the
/// case/invocation/toolkit context, is routed to a per-case CLEF (JSON) file that a judge could trace a finding
/// through. Drives the Runtime audit API directly — no MCP server or SIFT workstation required.
/// </summary>
[Collection("Audit")] // serialize: the audit logger is a process-wide static
public class AuditTrailTests
{
    [Fact]
    public void AuditCommandWritesEnrichedPerCaseClef()
    {
        var dir = Path.Combine(Path.GetTempPath(), "camel_audit_" + Guid.NewGuid().ToString("N"));
        Runtime.WithAuditLog(dir);
        try
        {
            // Simulate what the server/toolkit layers push: case → invocation → toolkit/operation, then a command.
            using (Runtime.PushAuditProperty("CaseId", "srl-2018-rd01"))
            using (Runtime.PushAuditProperty("InvocationId", "inv12345"))
            using (Runtime.PushAuditProperty("Toolkit", "MemoryAnalysisToolkit"))
            using (Runtime.PushAuditProperty("Operation", "WindowsNetScan"))
            {
                Runtime.AuditCommand("sift-host", "vol.py", "-f base-rd01-memory.img windows.netscan",
                    sudo: true, exitCode: 0, durationMs: 1234, completed: true);
            }
            Runtime.CloseAndFlushAuditLog(); // flush buffered events to disk

            var file = Path.Combine(dir, "audit-srl-2018-rd01.clef"); // routed by CaseId
            Assert.True(File.Exists(file), $"expected per-case audit file at {file}");
            var content = File.ReadAllText(file);

            // The full trace chain is present in one structured record.
            Assert.Contains("srl-2018-rd01", content);   // CaseId (also the file name)
            Assert.Contains("inv12345", content);         // InvocationId the agent cites
            Assert.Contains("MemoryAnalysisToolkit", content);
            Assert.Contains("WindowsNetScan", content);
            Assert.Contains("vol.py", content);           // the specific tool execution
            Assert.Contains("windows.netscan", content);
            Assert.Contains("sift-host", content);        // host it ran on
            Assert.Contains("command", content);          // EventType
        }
        finally
        {
            Runtime.CloseAndFlushAuditLog();
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public void DifferentCaseIdsRouteToDifferentFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "camel_audit_" + Guid.NewGuid().ToString("N"));
        Runtime.WithAuditLog(dir);
        try
        {
            using (Runtime.PushAuditProperty("CaseId", "case-a"))
                Runtime.AuditCommand("h", "a.sh", "", false, 0, 1, true);
            using (Runtime.PushAuditProperty("CaseId", "case-b"))
                Runtime.AuditCommand("h", "b.sh", "", false, 0, 1, true);
            Runtime.CloseAndFlushAuditLog();

            Assert.True(File.Exists(Path.Combine(dir, "audit-case-a.clef")));
            Assert.True(File.Exists(Path.Combine(dir, "audit-case-b.clef")));
            Assert.Contains("a.sh", File.ReadAllText(Path.Combine(dir, "audit-case-a.clef")));
            Assert.DoesNotContain("a.sh", File.ReadAllText(Path.Combine(dir, "audit-case-b.clef")));
        }
        finally
        {
            Runtime.CloseAndFlushAuditLog();
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}

[CollectionDefinition("Audit", DisableParallelization = true)]
public class AuditCollection { }
