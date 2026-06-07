namespace Camel.Toolkits.Models;

using System;
using System.Text.Json.Serialization;


public class WindowsInfo
{
    public string Value { get; set; } = "";
    public string Variable { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsPsList
{
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public string Fileoutput { get; set; } = "";
    public object? Handles { get; set; } = null;
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public int? SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public WindowsPsTree[] __children { get; set; } = [];
}

public class WindowsPsScan
{
    public DateTime CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public string Fileoutput { get; set; } = "";
    public object? Handles { get; set; }
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public int SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsSvcScan
{
    public string? Binary { get; set; }
    [JsonPropertyName("Binary (Registry)")]
    public string? BinaryRegistry { get; set; }
    public string Display { get; set; } = "";
    public string? Dll { get; set; }
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public int Order { get; set; }
    public int? PID { get; set; }
    public string Start { get; set; } = "";
    public string State { get; set; } = "";
    public string Type { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsCmdLine
{
    public string? Args { get; set; }
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsEnvVars
{
    public string Block { get; set; } = "";
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string Value { get; set; } = "";
    public string Variable { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsGetSids
{
    public string Name { get; set; } = "";
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string SID { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsPrivs
{
    public string Attributes { get; set; } = "";
    public string Description { get; set; } = "";
    public int PID { get; set; }
    public string Privilege { get; set; } = "";
    public string Process { get; set; } = "";
    public int Value { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsHandles
{
    public long GrantedAccess { get; set; }
    public long HandleValue { get; set; }
    public string? Name { get; set; }
    public long Offset { get; set; }
    public int PID { get; set; }
    public string Process { get; set; } = "";
    public string Type { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsMalFind
{
    public long CommitCharge { get; set; }
    public string Disasm { get; set; } = "";
    [JsonPropertyName("End VPN")]
    public long EndVPN { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Hexdump { get; set; } = "";
    public string? Notes { get; set; }
    public int PID { get; set; }
    public long PrivateMemory { get; set; }
    public string Process { get; set; } = "";
    public string Protection { get; set; } = "";
    [JsonPropertyName("Start VPN")]
    public long StartVPN { get; set; }
    public string Tag { get; set; } = "";
    public object[] __children { get; set; } = [];
}


public class WindowsPsTree
{
    public string Audit { get; set; } = "";
    public string Cmd { get; set; } = "";
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public object? Handles { get; set; }
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public string Path { get; set; } = "";
    public int? SessionId { get; set; }
    public int Threads { get; set; }
    public bool Wow64 { get; set; }
    public object[] __children { get; set; } = [];
}
