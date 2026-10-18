# tools

Security tooling for handling untrusted third-party and reference material, in support of the
**Project guardrails** in the root `CLAUDE.md`. Verdicts are recorded in the ledger,
`reference/README.md`.

All of these are **read-only** with respect to the material they inspect, except
`extract-and-scan.ps1`, which writes only into a new destination directory it creates. They are
PowerShell or Perl, per the scripting guardrail. Perl on this machine is the copy bundled with Git,
`C:/Git/usr/bin/perl.exe`, which is not on PowerShell's PATH; pass it forward-slash paths.

| Script | Use it to | Prints file content? |
|---|---|---|
| `scan-codepoints.pl` | Scan text for hidden or smuggled characters, homoglyphs and injection phrasing; census of all non-ASCII. Exit 0 clean, 1 review, 2 usage. | Only matched phrases and tokens |
| `runlen.pl` | Answer "is anything hidden?" by the longest run of invisible characters per file. | **No**: path and counts only |
| `inspect-zip.ps1` | Check an archive *before* extracting: zip bomb ratios, path traversal, symlink entries. | No |
| `zip-entry.ps1` | Read one entry without extracting, e.g. a symlink's target. | Yes, that one entry |
| `extract-and-scan.ps1` | Extract into a fresh directory, entry by entry with failures named, then run the scanner. | Writes the scan report to a file |
| `exec-surface.ps1` | Survey what would act if the material were built, run, installed, or opened in an editor or agent harness. | Matching lines, truncated |

## Order of use for a new archive

1. `inspect-zip.ps1`, and read any symlink targets with `zip-entry.ps1`.
2. `extract-and-scan.ps1` into a new directory outside the repo.
3. `runlen.pl` over the extraction if the scan reports invisible characters.
4. `exec-surface.ps1` if the material will ever be built or run.
5. Record the verdict, with the zip's SHA-256 and the scanner version, in `reference/README.md`.
6. Delete the extraction.

## Material that is attack content by design

Payload lists, prompt-injection catalogues and exploit write-ups are expected to light up the
scanner. **Explain those hits by location, category and count, not by printing the matching
text**: that is what `runlen.pl` is for. Record such trees with a hazard note in the ledger
rather than reproducing them.

## Keep this directory self-clean

These files are the guardrail's own tooling, so they must scan clean:

```powershell
& 'C:/Git/usr/bin/perl.exe' 'C:/Projects/Camel/tools/scan-codepoints.pl' 'C:/Projects/Camel/tools'
$LASTEXITCODE   # must be 0
```
