using System.Linq;

using Jint;
using Jint.Runtime.Interop;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Inference;

namespace Camel.Tests.Training;

/// <summary>
/// Verifies the anomaly façade is actually callable from the code-mode agent's JavaScript engine the way the MCP
/// server binds it (<c>MCPServer.cs</c>: <c>.SetValue("anomaly", new AnomalyDetectionToolkit())</c>) — i.e. that
/// Jint marshals a CLR <see cref="TimelineEvent"/>[] into the façade and a <see cref="TriageReport"/> back out, so a
/// script can go raw-events → triage → human-readable summary end to end.
/// </summary>
public class JsInteropTests
{
    [Fact]
    public void AgentScriptCanTriageTimelineEventsViaTheBoundFacade()
    {
        // Raw Plaso-style events: routine logons + one log-clear (1102) — the same shape Timeline.PsortAsync returns.
        var events = Enumerable.Range(1, 200)
            .Select(i => Raw(i, "[4624 / 0x1210] An account was logged on"))
            .Append(Raw(201, "[1102 / 0x044e] The audit log was cleared"))
            .ToArray();

        string captured = "";
        var engine = new Engine(o => o.AllowClr())
            .SetValue("log", new System.Action<string>(s => captured = s))
            .SetValue("events", events)
            .SetValue("anomaly", new AnomalyDetectionToolkit());

        // Exactly what an agent would write against the bound API.
        engine.Execute("var r = anomaly.TriageTimeline(events, 25); log(anomaly.Summarize(r));");

        Assert.Contains("worth review", captured);
        Assert.Contains("evtx:1102", captured);          // the log-clear surfaced in the shortlist reasons
    }

    private static TimelineEvent Raw(long ts, string message) =>
        new() { Timestamp = ts, DataType = "windows:evtx:record", TimestampDesc = "Creation Time", Message = message };
}
