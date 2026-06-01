namespace Camel.Environments;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

public abstract class AuditFileSystemInfo : IFileSystemInfo
{
    #region Constructors
    public AuditFileSystemInfo(AuditEnvironment env, string sep)
    {
        this.AuditEnvironment = env;
        this.PathSeparator = sep;        
    }
    #endregion

    #region Properties
    public abstract string FullName { get; protected set; }
    public abstract string Name { get; protected set; }
    public string PathSeparator { get; protected set; }
    public AuditEnvironment AuditEnvironment { get; protected set; }
    #endregion

    #region Abstract properties
    public abstract bool Exists { get; }
    #endregion

    #region Protected methods
    protected string EnvironmentExecute(string command, string args, [CallerMemberName] string memberName = "", [CallerFilePath] string fileName = "", [CallerLineNumber] int lineNumber = 0)
    {
        if (this.AuditEnvironment is null)
        {
            throw new InvalidOperationException("The AuditEnvironment property must be set to execute environment commands.");
        }                        
        var r = this.AuditEnvironment.Execute(command, args);
        if (r.Status == ProcessExecuteStatus.Completed)
        {
            this.AuditEnvironment.Debug("The command {0} {1} executed successfully. Output: {1}", command, args, r.StdOut);
            return r.StdOut;
        }

        else
        {

            this.AuditEnvironment.Debug("The command {0} {1} did not execute successfully. Output: {1}", command, args, r.StdOut + r.StdErr);
            return string.Empty;
        }

    }

    protected void EnvironmentCommandError(CallerInformation caller, string message_format, params object[] m)
    {
        if (this.AuditEnvironment is null)
        {
            throw new InvalidOperationException("The AuditEnvironment property must be set to execute environment commands.");
        }
        this.AuditEnvironment.Error(caller, message_format, m);
    }

    protected string CombinePaths(params string[] paths)
    {
        return paths.Aggregate((s1, s2) => s1 + this.PathSeparator + s2);
    }

    protected string[] GetPathComponents()
    {
        return this.FullName.Split(this.PathSeparator.ToArray()).ToArray();
    }
    #endregion
}

