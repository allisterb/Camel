namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Linq;
using System.Security;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Configuration;

public enum EnvironmentType
{
    Local,
    Ssh
}   

public abstract class AuditEnvironment : Runtime, IDisposable
{    
    #region Constructors
    public AuditEnvironment(EventHandler<EnvironmentEventArgs> message_handler, OperatingSystem os, LocalEnvironment host_environment)
    {
        this.OS = os;
        if (OS.Platform == PlatformID.Win32NT)
        {
            this.LineTerminator = "\r\n";
            this.PathSeparator = "\\";
        }
        else
        {
            this.LineTerminator = "\n";
            this.PathSeparator = "/";
        }
        this.MessageHandler = message_handler;
        this.HostEnvironment = host_environment;

    }

    public AuditEnvironment(OperatingSystem os, LocalEnvironment host_environment) : this(DefaultEnvironmentMessageHandler, os, host_environment) {}
    #endregion

    #region Abstract properties and methods
    public abstract bool FileExists(string file_path);
    public abstract bool DirectoryExists(string dir_path);
    public abstract CommandResult Execute(string command, string arguments,Dictionary<string, string>? EnvironmentVariables = null, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract Task<CommandResult> ExecuteAsync(string command, string arguments, Dictionary<string, string>? EnvironmentVariables = null, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract CommandResult ExecuteAsUser(string command, string arguments, string user, SecureString password, Action<string>? OutputDataReceived = null, Action<string>? OutputErrorReceived = null);
    public abstract AuditFileInfo ConstructFile(string file_path);
    public abstract AuditDirectoryInfo ConstructDirectory(string dir_path);
    public abstract Dictionary<AuditFileInfo, string> ReadFilesAsText(List<AuditFileInfo> files);

    /// <summary>Copies a file from this environment to <paramref name="localPath"/> and returns it (SCP for a remote
    /// SSH environment; a plain file copy locally), so a large output can be streamed/parsed from disk instead of
    /// captured through a command's stdout. Returns null on failure.</summary>
    public abstract FileInfo? GetFileAsLocal(string remotePath, string localPath);
    protected abstract TraceSource TraceSource { get; set; }
    #endregion

    #region Properties
    public bool IsWindows
    {
        get
        {
            if (this.OS != null && this.OS.Platform == PlatformID.Win32NT)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    public bool IsUnix
    {
        get
        {
            if (this.OS != null && this.OS.Platform == PlatformID.Unix)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }

    public bool IsMonoRuntime
    {
        get
        {
            return Type.GetType("Mono.Runtime") != null;
        }
    }

    public new string PathSeparator { get; protected set; } = string.Empty;
    
    public OperatingSystem OS { get; protected set; }

    public string? OSName { get; set; }

    public string? OSVersion { get; set; }

    public Dictionary<string, string>? OSEnvironmentVars { get; protected set; }

    public List<ProcessInfo>? OSProcesses { get; protected set; }

    public LocalEnvironment HostEnvironment { get; protected set; }

    public DirectoryInfo WorkDirectory { get; protected set; }

    internal string LineTerminator { get; set; }

    #endregion

    #region Concurrency limiting
    /// <summary>
    /// Maximum number of concurrent async command executions on this environment. <c>0</c> (default) means
    /// unlimited. A positive value bounds fan-out (e.g. a code-mode <c>Promise.all</c>) so a single session
    /// can't exhaust the connection's SSH channels or swamp the workstation. Typically set from config.
    /// </summary>
    public int MaxConcurrentExecutions { get; set; } = 0;

    private SemaphoreSlim? _executionLimiter;
    private readonly object _executionLimiterLock = new();

    // Lazily built (MaxConcurrentExecutions is usually assigned from config after construction). Null = unlimited.
    private SemaphoreSlim? ExecutionLimiter
    {
        get
        {
            if (MaxConcurrentExecutions <= 0) return null;
            if (_executionLimiter is null)
                lock (_executionLimiterLock) _executionLimiter ??= new SemaphoreSlim(MaxConcurrentExecutions);
            return _executionLimiter;
        }
    }

    /// <summary>
    /// Runs <paramref name="execute"/> under this environment's concurrency limit (see
    /// <see cref="MaxConcurrentExecutions"/>; 0 = unlimited). The wait honours the environment's cancellation
    /// token so a disconnect doesn't leave callers queued. Intended to wrap each <c>ExecuteAsync</c> override.
    /// </summary>
    protected async Task<CommandResult> RunWithLimitAsync(Func<Task<CommandResult>> execute)
    {
        var limiter = ExecutionLimiter;
        if (limiter is null) return await execute();

        using var linked = CancellationTokenSource.CreateLinkedTokenSource(Runtime.Ct, ExecuteCt);
        await limiter.WaitAsync(linked.Token);   // throws OCE if cancelled while queued (nothing to release)
        try { return await execute(); }
        finally { limiter.Release(); }
    }
    #endregion

    #region Cancellation
    // Backing source whose token is observed by every async Execute call on this environment. Cancelling
    // it (via CancelExecutions) aborts all in-flight and pending async commands — e.g. on client disconnect.
    private CancellationTokenSource executeCts = new();

    /// <summary>The token all async Execute methods on this environment observe. Trip it via <see cref="CancelExecutions"/>.</summary>
    public CancellationToken ExecuteCt => executeCts.Token;

    /// <summary>
    /// Cancels every in-flight and pending async command on this environment, then swaps in a fresh source
    /// so subsequent calls execute normally. The old source is intentionally not disposed: a caller may have
    /// read it but not yet built its linked token, and disposing it would make that read throw
    /// <see cref="ObjectDisposedException"/>; a plain (timer-less) source holds no unmanaged handle, so GC
    /// reclaims it safely once the cancellation callbacks have run.
    /// </summary>
    public void CancelExecutions()
    {
        var old = Interlocked.Exchange(ref executeCts, new CancellationTokenSource());
        old.Cancel();
    }

    /// <summary>
    /// Releases this environment's idle transport (e.g. an SSH connection) while keeping the environment object
    /// usable — the next command transparently reconnects. Lets the idle sweeper reclaim the expensive connection
    /// without discarding the session's in-memory state (its <c>Session</c> storage). The base implementation is a
    /// no-op (e.g. the local environment holds no connection to release). Returns true if a live connection was
    /// actually released.
    /// </summary>
    public virtual bool DisconnectIdle() => false;
    #endregion

    #region Methods
    public bool ExecuteCommand(string command, string arguments, out string output, bool admin = false)
    {
        string process_output = "", process_error = "";
        CommandResult? r;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        if (admin)
        {
            if (this.IsUnix)
            {
                r = this.Execute("sudo", command + " " + arguments);
            }
            else throw new NotImplementedException("ExecuteCommandAsAdmin is not implemented for Windows environments.");
        }
        else
        {
            r = this.Execute(command, arguments);
        }
        sw.Stop();
        // Audit the synchronous command path too (cleanup/plumbing and any sync tool call), so the per-case trail
        // is complete. Ambient case/execution/toolkit context is supplied from the log context as in the async path.
        AuditCommand(AuditHostName, command, arguments, admin, r.ExitCode, sw.ElapsedMilliseconds, r.IsCompleted);
        process_output = r.StdOut;
        process_error = r.StdErr;
        if (r.Status == ProcessExecuteStatus.Completed)
        {
            output = process_output.Trim();
            Debug("The command {0} {1} executed successfully. Output: {2}", command, arguments, output);
            return true;
        }
        else
        {
            output = process_output + process_error.Trim();            
            return false;
        }
    }

    public async Task<CommandResult> ExecuteCommandAsync(string command, string arguments, bool admin = false)
    {
        // Concurrency limiting is enforced in ExecuteAsync (the primitive both this wrapper and any direct
        // caller funnel through), so it is intentionally not applied here to avoid acquiring twice.
        CommandResult? r;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        if (admin)
        {
            if (this.IsUnix)
            {
                r = await this.ExecuteAsync("sudo", command + " " + arguments);
            }
            else throw new NotImplementedException("ExecuteCommandAsAdmin is not implemented for Windows environments.");
        }
        else
        {
            r = await this.ExecuteAsync(command, arguments);
        }
        sw.Stop();
        // Record this command in the per-case audit trail. CaseId/ExecutionId/Toolkit/Operation/Workflow are
        // enriched ambiently from the log context, so this single chokepoint ties every tool execution to the
        // case and agent step that drove it — the row a judge traces a finding back to.
        AuditCommand(AuditHostName, command, arguments, admin, r.ExitCode, sw.ElapsedMilliseconds, r.IsCompleted);
        if (r.Status == ProcessExecuteStatus.Completed)
        {
            Debug("The command {0} {1} executed successfully. Output: {2}", command, arguments, r.Output);
        }
        else
        {
            Debug("The command {0} {1} did not execute successfully. Output: {2}", command, arguments, r.Output);
        }
        return r;
    }

    /// <summary>
    /// The host name recorded in the audit trail for commands run on this environment. The base (local)
    /// environment reports the machine name; the SSH environment overrides this with the remote host.
    /// </summary>
    protected virtual string AuditHostName => System.Environment.MachineName;

    public virtual string GetOSName()
    {
        if (!string.IsNullOrEmpty(this.OSName)) return this.OSName;
        CallerInformation here = Here();
        string cmd = "", args = "";
        if (this.IsUnix)
        {
            cmd = "cat";
            args = "/etc/*release";
            string output;
            if (this.ExecuteCommand(cmd, args, out output, false) || !string.IsNullOrEmpty(output))
            {
                if (output.ToLower().Contains("ubuntu"))
                {
                    this.OSName = "ubuntu";
                }
                else if (output.ToLower().Contains("debian"))
                {
                    this.OSName = "debian";
                }
                else if (output.ToLower().Contains("centos"))
                {
                    this.OSName = "centos";
                }
                else if (output.ToLower().Contains("suse linux"))
                {
                    this.OSName = "suse";
                }
                else if (output.ToLower().Contains("red hat enterprise linux"))
                {
                    this.OSName = "rhel";
                }
                else if (output.ToLower().Contains("oracle linux server"))
                {
                    this.OSName = "oraclelinux";
                }
            }
            if (string.IsNullOrEmpty(this.OSName))
            {
                cmd = "lsb_release";
                args = "-a";
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    if (output.ToLower().Contains("ubuntu"))
                    {
                        this.OSName = "ubuntu";
                    }
                    else if (output.ToLower().Contains("debian"))
                    {
                        this.OSName = "debian";
                    }
                    else if (output.ToLower().Contains("centos"))
                    {
                        this.OSName = "centos";
                    }
                    else if (output.ToLower().Contains("suse linux"))
                    {
                        this.OSName = "suse";
                    }
                    else if (output.ToLower().Contains("oracle linux"))
                    {
                        this.OSName = "oracle";
                    }

                    else if (output.ToLower().Contains("red hat enterprise linux"))
                    {
                        this.OSName = "rhel";
                    }
                }
                if (string.IsNullOrEmpty(this.OSName))
                {
                    cmd = "stat";
                    args = "/etc/oracle-release";
                    if (this.ExecuteCommand(cmd, args, out output, false))
                    {
                        this.OSName = "oraclelinux";
                    }
                    else
                    {
                        cmd = "stat";
                        args = "/etc/centos-release";
                        if (this.ExecuteCommand(cmd, args, out output, false))
                        {
                            this.OSName = "centos";
                        }
                        else
                        {
                            cmd = "stat";
                            args = "/etc/redhat-release";
                            if (this.ExecuteCommand(cmd, args, out output, false))
                            {
                                this.OSName = "rhel";
                            }
                            else
                            {
                                Error("GetOSName() failed.");
                            }
                        }
                    }
                }
            }
            if (!string.IsNullOrEmpty(this.OSName))
            {
                Success("Detected operating system of environment is {0}.", this.OSName);
            }
            else
            {
                Warning("GetOSName() failed. Falling back to unix");
                this.OSName = "unix";
            }

        }
        return this.OSName;
    }

    public virtual string GetOSVersion()
    {
        if (!string.IsNullOrEmpty(this.OSVersion)) return this.OSVersion;
        CallerInformation here = Here();
        string cmd = "", args = "", version = "";
        if (this.IsUnix)
        {
            if (this.OSName == "ubuntu")
            {
                cmd = "lsb_release";
                args = "-sr ";
                string output;
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    version = output;
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    cmd = "bash";
                    args = "-c \"cat /etc/*release | grep -m 1 DISTRIB_RELEASE | cut -d '=\' -f2 && test \\${PIPESTATUS[0]} -eq 0\"";
                    if (this.ExecuteCommand(cmd, args, out output, false) && !string.IsNullOrEmpty(output))
                    {
                        version = output.Replace("Release:\t", string.Empty);
                        Debug(here, "GetOSVersion() returned {0}.", version);
                    }
                    else
                    {
                        Error("GetOSVersion() failed.");
                    }
                }

            }
            else if (this.OSName == "debian")
            {
                cmd = "cat";
                args = "/etc/debian_version";
                string output;
                if (this.ExecuteCommand(cmd, args, out output))
                {
                    version = output.Trim();
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    Error("GetOSVersion() failed.");
                }
            }
            else if (this.OSName == "centos")
            {
                cmd = "bash";
                args = "-c \"cat /etc/centos-release | cut -d' ' -f4 && test \\${PIPESTATUS[0]} -eq 0\"";
                string output;
                if (this.ExecuteCommand(cmd, args, out output, false))
                {
                    version = output.Trim();
                    Debug(here, "GetOSVersion() returned {0}.", version);
                }
                else
                {
                    cmd = "awk";
                    args = "'NR==1{print $3}' /etc/issue";
                    if (this.ExecuteCommand(cmd, args, out output, false))
                    {
                        version = output.Trim();
                        Debug(here, "GetOSVersion() returned {0}.", version);
                    }
                    else
                    {
                        Error("GetOSVersion() failed.");
                    }
                }
            }
            else if (this.OSName == "oraclelinux")
            {
                string output;
                cmd = "cat";
                args = "/etc/oracle-release";
                if (this.ExecuteCommand(cmd, args, out output, false) && !string.IsNullOrEmpty(output))
                {
                    version = output.Replace("Oracle Linux Server release ", string.Empty).Split('.').FirstOrDefault();
                }
                else
                {
                    Error("GetOSVersion() failed.");
                }
            }
            if (!string.IsNullOrEmpty(version))
            {
                this.OSVersion = version;
                Success("Detected operating system version of environment is {0}.", this.OSVersion);
            }
        }
        return this.OSVersion;
    }

    public virtual string OSExec(string command, string args)
    {
        CallerInformation here = Here();
        args = args + " 2>/dev/null";
        string output;
        if (this.ExecuteCommand(command, args, out output, false))
        {
            Debug("OSExec({0}, {1}) returned zero exit-code with stdout: {2}", command, args, output);
            return output;
        }
        else if (!string.IsNullOrEmpty(output))
        {
            Debug("OSExec({0}, {1}) returned non-zero exit-code with stdout: {2}", command, args, output);
            return output;
        }
        else
        {
            Debug("OSExec({0}, {1}) returned non-zero exit-code.", command, args);
            return string.Empty;
        }

    }

    public virtual string GetEnvironmentVar(string name)
    {
        CallerInformation here = Here();
        string var = "", cmd = "", args = "";
        if (this.IsWindows)
        {
            var = "%" + name + "%";
            cmd = "powershell";
            args = "(Get-Childitem env:" + name + ").Value";
        }
        else
        {
            var = "$" + name;
            cmd = "echo";
            args = var;
        }
        string output;
        if (this.ExecuteCommand(cmd, args, out output))
        {
            Debug(here, "GetEnvironmentVar({0}) returned {1}.", name, output);
            return output;
        }
        else
        {
            Error("GetEnvironmentVar({0}) failed.", var);
            return string.Empty;
        }
    }


    public virtual string GetUnixFileMode(string path, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        CallerInformation here = Here();
        if (this.IsWindows)
        {
            Error(here, "This method is not implemented in a Windows environment.");
            return string.Empty;
        }
        else
        {
            string output;
            if (this.ExecuteCommand("find", string.Format("{0} -prune -printf '%m'", path), out output))
            {
                Debug(here, "GetUnixFileMode({0}) returned {1}.", path, output);
                return output;
            }
            else
            {
                Debug(here, "Did not successfully execute GetUnixFileMode({0}).", path);
                return string.Empty;
            }
        }
    }

    public virtual string FindFiles(string path, string pattern, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        if (this.IsUnix)
        {
            CallerInformation here = Here();
            string output;
            string cmd = "find";
            string args = string.Format("{0} -name {1} -type f", path, pattern);
            if (this.ExecuteCommand(cmd, args, out output, false))
            {
                Debug(here, "FindFiles({0}, {1}) returned {2}.", path, pattern, output);
                return output;
            }
            else
            {
                string[] error = output.Split(this.LineTerminator.ToCharArray());
                if (error.All(e => e.EndsWith("Permission denied")))
                {
                    Debug(here, "FindFiles({0}, {1}) returned empty.", path, pattern);
                    return string.Empty;
                }
                else
                {
                    Error(here, "Did not successfully execute FindFiles({0}, {1}). Error: {2}.)", path, pattern, output);
                    return string.Empty;
                }
            }
                
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public virtual string FindDirectories(string path, string pattern, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        if (this.IsUnix)
        {
            CallerInformation here = Here();
            string output;
            string cmd = "find";
            string args = string.Format("{0} -name {1} -type d", path, pattern);
            if (this.ExecuteCommand(cmd, args, out output, false))
            {
                Debug(here, "FindDirectories({0}, {1}) returned {2}", path, pattern, output);
                return output;
            }
            else
            {
                Error(here, "Did not successfully execute FindDirectories({0}, {1}). Error: {2}.)", path, pattern, output);
                return string.Empty;
            }

        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public bool GetIsSymbolicLink(string f)
    {
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("stat", f, out output))
            {
                if (output.Contains("symbolic link"))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                this.Error("Did not successfully execute GetIsSymbolicLink({0}).", f);
                return false;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public string GetSymbolicLinkLocation(string f)
    {
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("ls", "-l " + f, out output))
            {
                if (output.Contains("->"))
                {
                    string l = output.Substring(output.IndexOf("->")).Trim();
                    Debug("GetSymbolicLinkLocation({0}) returned {1}.", f, l);
                    return l ;
                }
                else
                {
                    Debug("GetSymbolicLinkLocation({0}) returned null.", f);
                    return string.Empty;
                }
            }
            else
            {
                this.Error("Did not successfully execute GetSymbolicLinkLocation({0}).");
                return string.Empty;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }
    public virtual List<ProcessInfo> GetAllRunningProcesses()
    {
        if (this.OSProcesses != null)
        {
            return this.OSProcesses;
        }
        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("ps", "-eo uname,pid,start_time,args", out output, false))
            {
                string[] lines = output.Split('\n');
                if (!lines[0].StartsWith("USER"))
                {
                    this.Error("Could not parse output of ps command.");
                    return null;
                }
                List<ProcessInfo> p = new List<ProcessInfo>(lines.Length - 1);
                for (int i = 1; i < lines.Length; i++)
                {
                    string[] ps = Regex.Split(lines[i], @"\s+");
                    string u = ps[0];
                    string pid = ps[1];
                    string t = ps[2];
                    string c = string.Empty;
                    for (int j = 3; j < ps.Length; j++)
                    {
                        c = c + ps[j] + " ";
                    }
                    p.Add(new ProcessInfo(ps[0], int.Parse(ps[1]), ps[2], c.Trim()));
                }
                return this.OSProcesses = p;
            }
            else
            {
                this.Warning("Could not get running processes in environment.");
                this.Debug("Could not get running processes. Error: {0}", output);
                return this.OSProcesses = new List<ProcessInfo>();
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    public virtual Dictionary<string, string> GetEnvironmentVars()
    {
        if (this.OSEnvironmentVars != null)
        {
            return this.OSEnvironmentVars;
        }

        if (this.IsUnix)
        {
            string output;
            if (this.ExecuteCommand("printenv", string.Empty, out output))
            {
                string[] lines = output.Split('\n');
                
                Dictionary<string, string> vars = new Dictionary<string, string>(lines.Length);
                for (int i = 0; i < lines.Length; i++)
                {
                    string[] var = Regex.Split(lines[i], @"=");
                    vars.Add(var[0].Trim(), var[1].Trim());
                }
                return this.OSEnvironmentVars = vars;
            }
            else
            {
                this.Error("Could not get environment variables. Error: {0}", output);
                return null;
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }
    public string GetTimestamp()
    {
        return (DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds.ToString();
    }

    public SecureString ToSecureString(string s)
    {
        SecureString r = new SecureString();
        foreach (char c in s)
        {
            r.AppendChar(c);
        }
        r.MakeReadOnly();
        return r;
    }

    public string ToInsecureString(object o)
    {
        SecureString s = o as SecureString;
        if (s == null) throw new ArgumentException("Object is not of type SecureString.", "o");
        string r = string.Empty;
        IntPtr ptr = Marshal.SecureStringToBSTR(s);
        try
        {
            r = Marshal.PtrToStringBSTR(ptr);
        }
        finally
        {
            Marshal.ZeroFreeBSTR(ptr);
        }
        return r;
    }

    [DebuggerStepThrough]
    internal void Message(EventMessageType message_type, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(message_type, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Info(string message_format, params object[] message)
    {
        TraceSource.TraceInformation(message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.INFO, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Error(string message_format, params object[] message)
    {
        TraceSource.TraceEvent(TraceEventType.Error, 0, message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.ERROR, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(caller, EventMessageType.ERROR, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Error(Exception e)
    {
        OnMessage(new EnvironmentEventArgs(e));
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, Exception e)
    {
        OnMessage(new EnvironmentEventArgs(caller, e));
    }

    [DebuggerStepThrough]
    internal void Error(Exception e, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(e);
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, Exception e, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(caller, e);
    }

    [DebuggerStepThrough]
    internal void Error(AggregateException ae)
    {
        if (ae.InnerExceptions != null && ae.InnerExceptions.Count >= 1)
        {
            foreach (Exception e in ae.InnerExceptions)
            {
                Error(e);
            }
        }
    }
    

    [DebuggerStepThrough]
    internal void Error(AggregateException ae, string message_format, params object[] message)
    {
        Error(message_format, message);
        Error(ae);
    }

    [DebuggerStepThrough]
    internal void Error(CallerInformation caller, AggregateException ae, string message_format, params object[] message)
    {
        Error(caller, message_format, message);
        if (ae.InnerExceptions != null && ae.InnerExceptions.Count >= 1)
        {
            foreach (Exception e in ae.InnerExceptions)
            {
                Error(caller, e);
            }
        }
    }

    [DebuggerStepThrough]
    internal void Success(string message_format, params object[] message)
    {
        TraceSource.TraceEvent(TraceEventType.Information, 0, message_format, message);
        OnMessage(new EnvironmentEventArgs(EventMessageType.SUCCESS, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Warning(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.WARNING, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Status(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.STATUS, message_format, message));
    }

    [DebuggerStepThrough]
    internal void Progress(string operation, int total, int complete, TimeSpan? time = null)
    {
        OnMessage(new EnvironmentEventArgs(new OperationProgress(operation, total, complete, time)));
    }

    [DebuggerStepThrough]
    internal void Debug(CallerInformation caller, string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(caller, EventMessageType.DEBUG, message_format, message));
    }

    [DebuggerStepThrough]
    internal new void Debug(string message_format, params object[] message)
    {
        OnMessage(new EnvironmentEventArgs(EventMessageType.DEBUG, message_format, message));
    }

    internal CallerInformation Here([CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        CallerInformation c;
        c.Name = memberName;
        c.File = fileName;
        c.LineNumber = lineNumber;
        return c;
    }

    public static void DefaultEnvironmentMessageHandler(object? sender, EnvironmentEventArgs e)
    {

        if (e.MessageType == EventMessageType.DEBUG)
        {
            Runtime.Debug(e.Message);
        }
        else if (e.MessageType == EventMessageType.ERROR)
        {
            if (e.Exception != null)
            {
                Runtime.Error(e.Exception, e.Message);
            }
            else
            {

                Runtime.Error(e.Message);

            }
        }
        else
        {
            Runtime.Info(e.Message);
        }
    }

    public static AuditEnvironment CreateFromConfig(IConfigurationRoot config)
    {
        var environmentType = Enum.Parse<EnvironmentType>(GetRequiredValue(config, "SIFT:Environment"));
        // Optional cap on concurrent async executions (0/absent = unlimited).
        int maxConcurrent = int.TryParse(config["SIFT:MaxConcurrentExecutions"], out var n) ? n : 0;
        AuditEnvironment env;
        if (environmentType == EnvironmentType.Local)
        {
            env = new LocalEnvironment();
        }
        else if (environmentType == EnvironmentType.Ssh)
        {
            var host = GetRequiredValue(config, "SIFT:Host");
            var port = Int32.Parse(GetRequiredValue(config, "SIFT:Port"));
            var user = GetRequiredValue(config, "SIFT:User");
            var password = GetRequiredValue(config, "SIFT:Password");
            env = new SshAuditEnvironment("camel", host, port, user, password, new OperatingSystem(PlatformID.Unix, new Version("24.04.4")), new LocalEnvironment());
        }
        else throw new Exception($"Invalid environment type specified in configuration: {environmentType.ToString()}");
        env.MaxConcurrentExecutions = maxConcurrent;
        return env;
    }
    #endregion

    #region Events
    public event EventHandler<EnvironmentEventArgs>? MessageHandler;

    protected virtual void OnMessage(EnvironmentEventArgs e) => MessageHandler?.Invoke(this, e);               
    #endregion

    #region Fields
    
    #endregion

    #region Disposer and Finalizer
    private bool IsDisposed { get; set; }
    /// <summary> 
    /// /// Implementation of Dispose according to .NET Framework Design Guidelines. 
    /// /// </summary> 
    /// /// <remarks>Do not make this method virtual. 
    /// /// A derived class should not be able to override this method. 
    /// /// </remarks>         
    public void Dispose()
    {
        Dispose(true); // This object will be cleaned up by the Dispose method. // Therefore, you should call GC.SupressFinalize to // take this object off the finalization queue // and prevent finalization code for this object // from executing a second time. // Always use SuppressFinalize() in case a subclass // of this type implements a finalizer. GC.SuppressFinalize(this); }
    }

    protected virtual void Dispose(bool isDisposing)
    {
        // TODO If you need thread safety, use a lock around these 
        // operations, as well as in your methods that use the resource. 
        try
        {
            if (!this.IsDisposed)
            {
                // Explicitly set root references to null to expressly tell the GarbageCollector 
                // that the resources have been disposed of and its ok to release the memory 
                // allocated for them. 
                if (isDisposing)
                {
                    // Release all managed resources here.
                    _executionLimiter?.Dispose();
                }
                // Release all unmanaged resources here 
                // (example) if (someComObject != null && Marshal.IsComObject(someComObject)) { Marshal.FinalReleaseComObject(someComObject); someComObject = null; 
            }
        }
        finally
        {
            this.IsDisposed = true;
        }
    }

    ~AuditEnvironment()
    {
        this.Dispose(false);
    }
    #endregion
}
