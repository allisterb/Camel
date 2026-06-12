namespace Camel.Training;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Cheap, training-free content features distilled from an event's message — the leakage-safe alternative to
/// embedding the raw text (we keep aggregate <em>scalars</em>, never the literal string, so a model can't shortcut
/// on a path). After Studiawan 2020 (Ch. 7), which feeds a "bad-word count" and message length to its anomaly
/// model: a curated DFIR keyword dictionary is the unsupervised distillation of that thesis's GRU sentiment model,
/// and the standout idea this codebase adopts — it targets malicious <em>content</em> inside an otherwise-common
/// event type (e.g. an encoded-PowerShell download cradle among hundreds of benign 4104 script-block records),
/// which the type/sequence/timing detectors cannot see.
/// </summary>
public static class ContentSignals
{
    /// <summary>Character length of the message (0 for null/empty) — encoded blobs and verbose errors run long.</summary>
    public static int MsgLength(string? message) => message?.Length ?? 0;

    /// <summary>How many distinct suspicious keywords appear in the (case-insensitive) message.</summary>
    public static int BadWordCount(string? message)
    {
        if (string.IsNullOrEmpty(message)) return 0;
        var m = message.ToLowerInvariant();
        int n = 0;
        foreach (var w in BadWords) if (m.Contains(w)) n++;
        return n;
    }

    /// <summary>The keywords found in <paramref name="message"/> — for the detector's human-readable reason.</summary>
    public static string[] BadWordsIn(string? message)
    {
        if (string.IsNullOrEmpty(message)) return [];
        var m = message.ToLowerInvariant();
        return BadWords.Where(m.Contains).ToArray();
    }

    // Offensive-PowerShell download cradles, encoding/obfuscation, LOLBins, and credential/log-tamper tooling. Kept
    // small and high-precision (a hit should genuinely warrant a look); substring-matched against the lower-cased
    // message. NB: keep this list in sync with the SRL eval staging script (see SrlAnomalyEvalTests regen recipe).
    private static readonly string[] BadWords =
    [
        "downloadstring", "downloadfile", "downloaddata", "net.webclient", "webclient",
        "invoke-expression", "iex ", "frombase64string", "-encodedcommand", "-enc ", "-e ",
        "-nop", "-noprofile", "-windowstyle hidden", "-w hidden", "bypass",
        "invoke-mimikatz", "mimikatz", "reflection.assembly", "shellcode", "downloadcradle",
        "bitsadmin", "certutil", "regsvr32", "rundll32", "mshta", "wscript", "cscript",
        "psexec", "wmic", "vssadmin delete", "wevtutil cl", "schtasks /create", "sc create",
    ];
}
