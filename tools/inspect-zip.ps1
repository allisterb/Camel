<#
.SYNOPSIS
    Read-only inspection of zip archives BEFORE extracting them.
.DESCRIPTION
    Extraction is where a hostile archive gets to act, so check it first. For each zip, reports:
      - size and compression ratios (a zip bomb has an extreme ratio)
      - entries with path traversal ('..'), absolute paths, or drive letters (zip slip)
      - Unix symlink entries (a link can point extraction outside the target directory;
        read a link's target with zip-entry.ps1)
      - the largest entries, the top-level folder(s), and the file-type mix
    Opens each archive for reading only; nothing is extracted or written.
.EXAMPLE
    .\tools\inspect-zip.ps1 -Zips reference\projects\hacktricks-master.zip
#>
param([Parameter(Mandatory)][string[]]$Zips)
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($z in $Zips) {
    $a = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $z).Path)
    try {
        $e = $a.Entries
        $comp = ($e | Measure-Object CompressedLength -Sum).Sum
        $full = ($e | Measure-Object Length -Sum).Sum
        $files = @($e | Where-Object { $_.Name -ne '' })
        $trav = @($e | Where-Object { $_.FullName -match '(^|[\\/])\.\.([\\/]|$)' -or $_.FullName -match '^[\\/]' -or $_.FullName -match '^[A-Za-z]:' })
        # Unix mode lives in the high 16 bits of ExternalAttributes; S_IFLNK = 0xA000.
        $links = @($e | Where-Object { (($_.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000 })
        $maxRatio = ($e | Where-Object { $_.CompressedLength -gt 0 } | ForEach-Object { $_.Length / $_.CompressedLength } | Measure-Object -Maximum).Maximum
        $tops = $e | ForEach-Object { ($_.FullName -split '[\\/]')[0] } | Sort-Object -Unique
        "=== $(Split-Path $z -Leaf) ==="
        "entries: $($e.Count) ($($files.Count) files)  compressed: {0:N1} MB  uncompressed: {1:N1} MB  overall ratio: {2:N1}x  max entry ratio: {3:N0}x" -f ($comp/1MB), ($full/1MB), ($full/[math]::Max($comp,1)), $maxRatio
        "top-level folder(s): $($tops -join ', ')"
        "path-traversal / absolute entries: $($trav.Count)"; $trav | Select-Object -First 10 | ForEach-Object { "   $($_.FullName)" }
        "symlink entries: $($links.Count)"; $links | Select-Object -First 10 | ForEach-Object { "   $($_.FullName)" }
        "largest entries:"; $e | Sort-Object Length -Descending | Select-Object -First 5 | ForEach-Object { "   {0,10:N1} MB  {1}" -f ($_.Length/1MB), $_.FullName }
        "file types (top 12): " + (($files | ForEach-Object { [IO.Path]::GetExtension($_.Name).ToLower() } | Group-Object | Sort-Object Count -Descending | Select-Object -First 12 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  ')
    } finally { $a.Dispose() }
}
