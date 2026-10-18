<#
.SYNOPSIS
    Safely extracts a zip into a NEW, empty directory, then runs scan-codepoints.pl over it.
.DESCRIPTION
    Run inspect-zip.ps1 first. Then this:
      - refuses to reuse an existing destination, so every extraction lands in a fresh directory;
      - extracts entry by entry, checking each target path resolves INSIDE the destination
        (defence in depth against zip slip, even when the inspection found none);
      - records every failed entry by name instead of aborting, so a file that antivirus
        blocks, or a case-only name collision on Windows, is a named gap rather than a
        silently short scan;
      - re-counts files on disk afterwards, because antivirus can remove a file after a
        successful write;
      - scans the result with scan-codepoints.pl (found next to this script) and writes the
        extraction log and the full scan report to -OutFile.
    Exit status is the scanner's: 0 clean, 1 needs review, 2 usage error.
    Delete the destination when finished; the zip's SHA-256 is what a ledger verdict should cite.
.EXAMPLE
    .\tools\extract-and-scan.ps1 -Zip reference\projects\x.zip -Dest $env:TEMP\scan-x -OutFile $env:TEMP\scan-x.out
#>
param(
    [Parameter(Mandatory)][string]$Zip,
    [Parameter(Mandatory)][string]$Dest,
    [Parameter(Mandatory)][string]$OutFile
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

# Perl: on PATH if available, else the copy Git for Windows ships beside git.exe (<git root>/usr/bin).
function Find-Perl {
    $p = Get-Command perl -ErrorAction SilentlyContinue
    if ($p) { return $p.Source }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $cand = Join-Path (Split-Path (Split-Path $git.Source -Parent) -Parent) 'usr/bin/perl.exe'
        if (Test-Path -LiteralPath $cand) { return $cand }
    }
    throw 'perl not found: not on PATH, and no Git-for-Windows perl beside git.exe.'
}
$perl    = Find-Perl
$scanner = Join-Path $PSScriptRoot 'scan-codepoints.pl'
if (-not (Test-Path -LiteralPath $scanner)) { throw "scanner not found next to this script: $scanner" }

$zipPath = (Resolve-Path -LiteralPath $Zip).Path
if (Test-Path -LiteralPath $Dest) { throw "Destination already exists, refusing to reuse it: $Dest" }
New-Item -ItemType Directory -Path $Dest | Out-Null
$destFull = [IO.Path]::GetFullPath($Dest).TrimEnd('\') + '\'

$log = New-Object System.Collections.Generic.List[string]
$ok = 0; $failed = New-Object System.Collections.Generic.List[string]
$sw = [Diagnostics.Stopwatch]::StartNew()
$a = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    foreach ($e in $a.Entries) {
        $target = [IO.Path]::GetFullPath((Join-Path $destFull ($e.FullName -replace '/', '\')))
        if (-not $target.StartsWith($destFull, [StringComparison]::OrdinalIgnoreCase)) {
            $failed.Add("OUTSIDE-DEST: $($e.FullName)"); continue
        }
        if ($e.Name -eq '') { [IO.Directory]::CreateDirectory($target) | Out-Null; continue }
        try {
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $false)
            $ok++
        } catch { $failed.Add("$($e.FullName): $($_.Exception.Message)") }
    }
} finally { $a.Dispose() }

$onDisk = (Get-ChildItem -LiteralPath $Dest -Recurse -File -Force | Measure-Object).Count
$log.Add("extracted $ok file(s) in $([int]$sw.Elapsed.TotalSeconds)s; on disk now: $onDisk; failed: $($failed.Count)")
$failed | Select-Object -First 50 | ForEach-Object { $log.Add("   FAILED $_") }
if ($failed.Count -gt 50) { $log.Add("   ... and $($failed.Count - 50) more") }

$sw.Restart()
$scan = & $perl ($scanner -replace '\\', '/') ($Dest -replace '\\', '/') | ForEach-Object { "$_" }
$code = $LASTEXITCODE
$log.Add("scan exit $code in $([int]$sw.Elapsed.TotalSeconds)s")
Set-Content -LiteralPath $OutFile -Value ($log + '' + $scan) -Encoding UTF8
"done: $zipPath -> $OutFile ($($log[0]); scan exit $code)"
exit $code
