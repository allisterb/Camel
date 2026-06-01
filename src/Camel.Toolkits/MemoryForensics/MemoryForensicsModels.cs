namespace Camel.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public class WindowsPsList
{    
    public DateTime CreateTime { get; set; }
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


public class WindowsPsTree
{
    public string Audit { get; set; } = "";
    public string Cmd { get; set; } = "";
    public DateTime CreateTime { get; set; }
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
