namespace Camel;

using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

public class LoggerOp :  IDisposable
{
    public LoggerOp(ILogger l, string opName, params object[] args)
    {
        timer.Start();
        this.l = l;
        this.opName = opName;   
        this.l.LogInformation(opName + "...", args);
    }

    public void Complete()
    {
        timer.Stop();
        l.LogInformation("{0} completed in {1}ms.", opName, timer.ElapsedMilliseconds);
        isCompleted = true;
    }

    public void Abandon()
    {
        timer.Stop();
        isAbandoned = true;
        l.LogError("{0} abandoned after {1}ms.", opName, timer.ElapsedMilliseconds);
    }

    public void Dispose()
    {
        if (timer.IsRunning) timer.Stop();
        if (!(isCompleted || isAbandoned))
        {
            isAbandoned = true;
            l.LogError("{0} abandoned after {1}ms.", opName, timer.ElapsedMilliseconds);
        }
    }
    public ILogger l;

    public string opName = "";

    public Stopwatch timer = new Stopwatch();

    protected bool isCompleted = false;

    protected bool isAbandoned = false;
}