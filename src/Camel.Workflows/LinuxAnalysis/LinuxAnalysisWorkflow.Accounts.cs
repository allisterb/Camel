namespace Camel.Workflows;

using System;
using System.Collections.Generic;
using System.Linq;

using Camel.Toolkits.Models;
using Camel.Workflows.Models;

public partial class LinuxAnalysisWorkflow
{
    /// <summary>
    /// Reviews local accounts and sudo grants on a mounted root for backdoor/escalation indicators: any account
    /// other than <c>root</c> with UID 0; accounts with an empty password; non-root service accounts
    /// (UID &lt; 1000) that nonetheless have an interactive login shell; and sudoers rules granting passwordless
    /// or unrestricted (ALL) access. Returns the full account/sudoers inventory plus the flagged findings.
    /// </summary>
    /// <param name="rootDir">The mounted root, e.g. <c>/mnt/linux</c>.</param>
    public async Task<WorkflowResult<UserAccountReport>> AnalyzeUserAccountsAsync(string rootDir)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing Linux user accounts under {0}", rootDir);

        var accounts = await LinuxAnalysis.UserAccountsAsync(rootDir);
        if (accounts is null)
            return WorkflowResult<UserAccountReport>.Failure(
                $"Could not read '{Combine(rootDir, "etc/passwd")}'; the path may be wrong or the volume not mounted.");
        var sudoers = await LinuxAnalysis.SudoersAsync(rootDir) ?? [];

        var findings = new List<AccountFinding>();
        foreach (var a in accounts)
        {
            if (a.Uid == 0 && a.Username != "root")
                findings.Add(new AccountFinding { Username = a.Username, Issue = "uid0-extra", Detail = "Non-root account with UID 0 (full superuser)." });
            if (a.PasswordState == "empty")
                findings.Add(new AccountFinding { Username = a.Username, Issue = "empty-password", Detail = $"Account logs in with no password (shell {a.Shell})." });
            if (a.IsSystemAccount && a.Uid != 0 && a.HasLoginShell)
                findings.Add(new AccountFinding { Username = a.Username, Issue = "service-account-login-shell", Detail = $"System account (UID {a.Uid}) has an interactive shell {a.Shell}." });
        }
        foreach (var r in sudoers)
        {
            if (r.NoPasswd)
                findings.Add(new AccountFinding { Username = r.Principal ?? "?", Issue = "sudo-nopasswd", Detail = $"Passwordless sudo in {r.Source}: {Truncate(r.Raw, 120)}" });
            else if (r.GrantsAll && r.Principal is not ("root" or "%sudo" or "%admin" or "%wheel"))
                findings.Add(new AccountFinding { Username = r.Principal ?? "?", Issue = "sudo-all", Detail = $"Unrestricted sudo (ALL) in {r.Source}: {Truncate(r.Raw, 120)}" });
        }

        op.Complete();
        var report = new UserAccountReport
        {
            Accounts = accounts,
            SudoRules = sudoers,
            Findings = findings.ToArray(),
            TotalAccounts = accounts.Length,
        };
        return WorkflowResult<UserAccountReport>.Success(report,
            findings.Count == 0
                ? $"{accounts.Length} account(s); no account/sudo anomalies flagged."
                : $"{accounts.Length} account(s); {findings.Count} finding(s): " +
                  string.Join("; ", findings.Take(5).Select(f => $"{f.Username} ({f.Issue})")) +
                  (findings.Count > 5 ? ", …" : "") + ".");
    }
}
