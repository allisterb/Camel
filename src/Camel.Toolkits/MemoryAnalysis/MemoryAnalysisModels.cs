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
    public DateTime? CreateTime { get; set; }
    public DateTime? ExitTime { get; set; }
    public string Fileoutput { get; set; } = "";
    public object? Handles { get; set; }
    public string ImageFileName { get; set; } = "";
    public long OffsetV { get; set; }
    public int PID { get; set; }
    public int PPID { get; set; }
    public int? SessionId { get; set; }
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

public class WindowsNetStat
{
    public long Offset { get; set; }
    public string Proto { get; set; } = "";
    public string LocalAddr { get; set; } = "";
    public int LocalPort { get; set; }
    public string ForeignAddr { get; set; } = "";
    public int ForeignPort { get; set; }
    public string State { get; set; } = "";
    public int? PID { get; set; }
    public string Owner { get; set; } = "";
    public DateTime? Created { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsNetScan
{
    public long Offset { get; set; }
    public string Proto { get; set; } = "";
    public string LocalAddr { get; set; } = "";
    public int LocalPort { get; set; }
    public string ForeignAddr { get; set; } = "";
    public int ForeignPort { get; set; }
    public string State { get; set; } = "";
    public int? PID { get; set; }
    public string Owner { get; set; } = "";
    public DateTime? Created { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsDllList
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public int LoadCount { get; set; }
    public DateTime? LoadTime { get; set; }
    public string? Name { get; set; }
    public int PID { get; set; }
    public string? Path { get; set; }
    public string Process { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsGetServiceSids
{
    public string SID { get; set; } = "";
    public string Service { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsModules
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsModScan
{
    public long Base { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public string Path { get; set; } = "";
    public long Size { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsFileScan
{
    public string Name { get; set; } = "";
    public long Offset { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsVadInfo
{
    public long CommitCharge { get; set; }
    [JsonPropertyName("End VPN")]
    public long EndVPN { get; set; }
    public string? File { get; set; }
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public long Offset { get; set; }
    public int PID { get; set; }
    public long Parent { get; set; }
    public long PrivateMemory { get; set; }
    public string Process { get; set; } = "";
    public string Protection { get; set; } = "";
    [JsonPropertyName("Start VPN")]
    public long StartVPN { get; set; }
    public string Tag { get; set; } = "";
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryHiveList
{
    [JsonPropertyName("File output")]
    public string FileOutput { get; set; } = "";
    public string FileFullPath { get; set; } = "";
    public long Offset { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryPrintKey
{
    public string Data { get; set; } = "";
    [JsonPropertyName("Hive Offset")]
    public long HiveOffset { get; set; }
    public string Key { get; set; } = "";
    [JsonPropertyName("Last Write Time")]
    public DateTime? LastWriteTime { get; set; }
    public string? Name { get; set; }
    public string Type { get; set; } = "";
    public bool? Volatile { get; set; }
    public object[] __children { get; set; } = [];
}

public class WindowsRegistryUserAssist
{
    public int? Count { get; set; }
    [JsonPropertyName("Focus Count")]
    public int? FocusCount { get; set; }
    [JsonPropertyName("Hive Name")]
    public string HiveName { get; set; } = "";
    [JsonPropertyName("Hive Offset")]
    public long HiveOffset { get; set; }
    public int? ID { get; set; }
    [JsonPropertyName("Last Updated")]
    public DateTime? LastUpdated { get; set; }
    [JsonPropertyName("Last Write Time")]
    public DateTime? LastWriteTime { get; set; }
    public string? Name { get; set; }
    public string Path { get; set; } = "";
    [JsonPropertyName("Raw Data")]
    public string RawData { get; set; } = "";
    [JsonPropertyName("Time Focused")]
    public string? TimeFocused { get; set; }
    public string Type { get; set; } = "";
    public WindowsRegistryUserAssist[] __children { get; set; } = [];
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
    public WindowsPsTree[] __children { get; set; } = [];
}
