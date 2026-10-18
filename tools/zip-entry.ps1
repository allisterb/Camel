<#
.SYNOPSIS
    Prints one zip entry's content as text, WITHOUT extracting the archive.
.DESCRIPTION
    Use it to read a symlink entry's target (for a Unix symlink entry the stored content IS the
    link target) or to look at one small file before deciding whether to extract. Prints the
    entry's length and Unix mode too. Read-only.
    Do not use it to print payload-bearing files from offensive-security material.
.EXAMPLE
    .\tools\zip-entry.ps1 -Zip reference\projects\hacktricks-master.zip -Entry hacktricks-master/README.md
#>
param([Parameter(Mandatory)][string]$Zip, [Parameter(Mandatory)][string]$Entry)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$a = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Zip).Path)
try {
    $e = $a.GetEntry($Entry)
    if (-not $e) { "no such entry: $Entry"; exit 1 }
    $s = $e.Open(); $ms = New-Object IO.MemoryStream; $s.CopyTo($ms); $s.Dispose()
    $b = $ms.ToArray()
    "entry: $Entry  length: $($b.Length) bytes  unix mode: 0x{0:X4}" -f (($e.ExternalAttributes -shr 16) -band 0xFFFF)
    "content: [" + [Text.Encoding]::UTF8.GetString($b) + "]"
} finally { $a.Dispose() }
