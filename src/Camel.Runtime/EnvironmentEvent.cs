namespace Camel.Environments;

using System;
using System.Threading;

public struct CallerInformation
{
    public string Name;
    public string File;
    public int LineNumber;

    public CallerInformation(string name, string file, int line_number)
    {
        this.Name = name;
        this.File = file;
        this.LineNumber = line_number;
    }
}

public struct OperationProgress
{
    public string Operation;
    public int Total;
    public int Complete;
    public TimeSpan? Time;

    public OperationProgress(string op, int total, int complete, TimeSpan? time)
    {
        this.Operation = op;
        this.Total = total;
        this.Complete = complete;
        this.Time = time;
    }
}
public enum EventMessageType
{
    SUCCESS = 0,
    ERROR = 1,
    INFO = 2,
    WARNING = 3,
    STATUS = 4,
    PROGRESS = 5,
    DEBUG = 6,
}

public class EnvironmentEventArgs
{
    #region Properties
    public EventMessageType MessageType { get; protected set; }
    public Thread CurrentThread;
    public string Message { get; protected set; }
    public DateTime DateTime { get; protected set; } = DateTime.UtcNow;
    public CallerInformation? Caller { get; protected set; }
    public Exception? Exception { get; protected set; }
    public OperationProgress? Progress { get; protected set; }
    public string EnvironmentLocation { get; internal set; } = "";
    #endregion

    #region Constructors
    public EnvironmentEventArgs(EventMessageType message_type, string message)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.MessageType = message_type;
        this.Message = message;
    }

    public EnvironmentEventArgs(EventMessageType message_type, string message_format, object[] m)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.MessageType = message_type;
        this.Message = string.Format(message_format, m);
    }

    public EnvironmentEventArgs(CallerInformation caller, EventMessageType message_type, string message_format, object[] m)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.Caller = caller;
        this.MessageType = message_type;
        this.Message = string.Format(message_format, m);
    }

    public EnvironmentEventArgs(CallerInformation caller, Exception e)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.Caller = caller;
        this.MessageType = EventMessageType.ERROR;
        this.Message = string.Format("Exception occurred.");
        this.Exception = e;
    }

    public EnvironmentEventArgs(Exception e)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.MessageType = EventMessageType.ERROR;
        this.Message = string.Format("Exception occurred.");
        this.Exception = e;
    }

    public EnvironmentEventArgs(OperationProgress p)
    {
        this.CurrentThread = Thread.CurrentThread;
        this.MessageType = EventMessageType.PROGRESS;
        this.Progress = p;
        this.Message = string.Format("{0} {1} of {2}", p.Operation, p.Complete, p.Total);
        if (p.Time.HasValue)
        {
            this.Message += string.Format(" in {0} ms.", p.Time.Value.Milliseconds);
        }
    }
    #endregion
}
