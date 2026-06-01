namespace Camel;

using System;

public enum ProcessExecuteStatus
{
    Unknown = -99,
    FileNotFound = -1,
    Completed = 0,
    Error = 1
}

public class CommandResult
{
    public ProcessExecuteStatus Status { get; set; }
    public string StdOut { get; set; }  
    public string StdErr { get; set; }
    public int? ExitCode { get; set; }   

    public CommandResult(ProcessExecuteStatus status, string std_out, string std_err, int? exit_code)
    {
        this.Status = status;
        this.StdOut = std_out;
        this.StdErr = std_err;
        this.ExitCode = exit_code;
    }
}
