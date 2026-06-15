# Incident Report - Case SRL-2018 (Stark Research Labs)

Principal DFIR analyst: Camel code-mode investigation against SANS SIFT workstation.
Domain: shieldbase.lan (Stark Research Labs / "SRL"). All timestamps UTC.
Every claim cites the Camel audit handle `[audit] execution=<id>` (traceable in
`logs/audit-SRL-2018.clef`) and the SDK method that produced it.

---

## Case evidence

Registered with `SetEvidence` (10 items). No hashes were supplied in the case
description, so integrity verification (`VerifyEvidence`) was skipped (nothing to
compare against). Disk-image acquisition metadata was read from the EWF containers
(`DiskAnalysisToolkit.EwfInfoAsync`, exec efbeeea1) and memory-capture times from
Volatility (`MemoryAnalysisToolkit.WindowsInfoAsync`, exec c9921405).

| File | Supplied hash (type) | Verified |
|------|----------------------|----------|
| base-dc-cdrive.E01 (dc01, DC) | none supplied | not verified; EWF case=20180905-001, examiner Clint Barton, acquired 2018-09-07 21:13 UTC |
| base-dc-memory.img (dc01) | none supplied | not verified; Volatility SystemTime 2018-09-06 22:57 UTC |
| base-rd-01-cdrive.E01 (rd-01, RDS) | none supplied | not verified; EWF acquired 2018-09-07 01:43 UTC |
| base-rd01-memory.img (rd-01) | none supplied | not verified; SystemTime 2018-09-06 18:57 UTC |
| base-rd-02-cdrive.E01 (rd-02, RDS) | none supplied | not verified; EWF acquired 2018-09-07 23:14 UTC |
| base-rd-02-memory.img (rd-02) | none supplied | not verified; SystemTime 2018-09-06 20:30 UTC |
| base-file-cdrive.E01 (file server) | none supplied | not verified; EWF acquired 2018-09-07 16:52 UTC |
| base-file-memory.img (file server) | none supplied | not verified; SystemTime 2018-09-06 19:28 UTC |
| base-wkstn-01-mem.img (wkstn-01) | none supplied | not verified; SystemTime 2021-09-16 03:05 UTC -- NOT 2018 incident evidence (see Gaps) |
| base-wkstn-05-memory.img (wkstn-05) | none supplied | not verified; SystemTime 2018-09-06 19:51 UTC |

Chain of custody: 9 of 10 items are the SRL 2018-09-06/07 acquisition (FTK Imager /
F-Response, case 20180905-001, examiner Clint Barton). The examiner's domain account
`cbarton-a` and the forensic station BASE-HUNT (172.16.5.25 / 172.16.5.28, also
172.16.5.50 via the F-Response `subject_srv.exe` agent on port 3262/5682) appear in the
logs as legitimate acquisition activity and were excluded from attacker attribution.

---

## Executive summary

Stark Research Labs suffered a domain-wide intrusion by an external threat actor whose
objective was the proprietary "Carbonadium" carbon/alloy research. The actor operated a
Cobalt-Strike-style SMB/named-pipe beacon (named pipe `MSSE-<n>-server`) with an internal
C2 at 172.16.4.10[:8080] and an external staging/C2 domain `squirreldirectory[.]com`. The
actor used valid, stolen domain credentials -- chiefly the SQL service account
`shieldbase\spsql` (a service account performing interactive RDP, the central anomaly) --
to move laterally by RDP and SMB across the Remote Desktop Services estate, the file
server, and workstations; ran PowerView for AD reconnaissance; dumped the entire Active
Directory database (NTDS.dit) from the domain controller via `ntdsutil` IFM; staged SRL's
carbon/alloy research (including the "Carbonadium Development Plan") for theft; and cleared
the file server's Security event log to cover its tracks.

Overall confidence: HIGH for the scope, tooling, credential theft, lateral movement, and
data targeting (each corroborated across memory, disk, event-log, and execution
artifacts). The precise initial-access vector and "patient zero" are MEDIUM/LOW (the
earliest-source host BASE-RD-04 / 172.16.6.14 was not imaged and no phishing email was
found). Off-network exfiltration is assessed as likely (via the C2 channel) but not
directly proven (no packet capture).

### Answers to the case questions

1. Initial access and System Zero.
   - The earliest attacker activity observed is RDP/network logons originating from
     172.16.6.14 (BASE-RD-04, a Remote Desktop Services host) using valid domain accounts
     `nromanoff` then `spsql`, beginning 2018-08-23 21:36 UTC. BASE-RD-04 is the most
     likely patient-zero within our visibility but was NOT imaged (no disk or memory).
   - The initial-access *vector* (delivery) is not confirmed: no phishing/malspam was
     found in the available mailboxes, and BASE-RD-04 was not captured. The actor already
     possessed valid credentials by 2018-08-23; the abuse of a SQL *service* account for
     interactive RDP indicates prior credential theft (Kerberoasting of the spsql SPN or
     LSASS harvesting are the leading candidates). Recorded for human judgement.

2. Lateral movement (order and method).
   - 172.16.6.14 (BASE-RD-04) -> rd-01 (172.16.6.11), RDP, 2018-08-28 21:39 UTC.
   - From rd-01: broad `spsql` explicit-credential (4648) spray 2018-08-28..30 to the file
     server (172.16.4.5), 172.16.4.6, 172.16.4.7, 172.16.5.20, rd-02 (172.16.6.12),
     172.16.6.13/15/16, and 172.16.7.11-7.16 (incl. wkstn-05 = 172.16.7.15).
   - rd-01 -> rd-02, RDP, 2018-08-31 00:17 UTC.
   - rd-01 -> DC (172.16.4.4), explicit-credential, 2018-09-05 12:14 UTC.
   - Methods: RDP (logon type 10), SMB admin-share (c$/ADMIN$) tool push + remote
     execution (PsExec/service style), and a scheduled task. Tools were copied into
     `C:\Windows\Temp\perfmon\` on each host (UNC c$ execution paths recorded in rd-01's
     Shimcache prove rd-01 was the push pivot).

3. Credential theft and privilege escalation.
   - Technique: full Active Directory database dump via `ntdsutil` IFM on the DC -
     `ntds.dit` + `SYSTEM` + `SECURITY` hives written to `C:\temp\Active Directory\` and
     `C:\temp\registry\` (run by `spsql`, 2018-09-05 12:14 UTC). This yields every domain
     hash, including krbtgt (golden-ticket capable) and all Domain Admins.
   - Compromised accounts: `spsql` (primary), `rsydow-a` (Domain-Admin-level; used it to
     reset a domain password), `nromanoff` (early), and `tdungan` (credentials used).
     `tyler.oslund`'s domain password was reset by `rsydow-a` on the DC (2018-09-06 01:37
     UTC).
   - Domain Admin obtained: YES (NTDS dump + DA-level account manipulation on the DC).
     No skeleton-key implant was found in DC memory (offline golden-ticket abuse remains
     possible from the stolen ntds.dit).

4. Malware, tooling and persistence.
   - Implant: Cobalt-Strike-style SMB/named-pipe beacon. `PerfSvc.exe` (file server,
     SHA256 e722dd42...) is the service-based variant creating named pipe `MSSE-<n>-server`
     and spawning rundll32; `p.exe` (rd-01, SHA256 7fa4f6cc..., UPX-packed) is the packed
     beacon. Corroborated by the file server's powershell-spawning-30+rundll32 memory
     pattern.
   - Tooling: `C:\Windows\Temp\perfmon\` toolset (p.exe, pa.exe, pb.exe, ri.exe, sd.exe,
     a masquerading `csrss.exe`, PerfView.exe, volrest.exe, n.ps1), BrowsingHistoryView.exe
     (recon), PowerSploit/PowerView.ps1 (AD recon), a base64 gzip PowerShell stager, and
     `ntdsutil` (LOLBIN, NTDS dump).
   - Persistence: rd-01 scheduled task `\Collect Background Statistics` (author
     `shieldbase\spsql`) launching `C:\Windows\Temp\1.bat`; file server `PerfSvc.exe`
     service stub.

5. Data targeting and exfiltration.
   - Targeted data: SRL's carbon/alloy research, including `Carbonadium Development Plan`
     (rd-02, jpallen; spsql opened it) and the carbon research repository on the file
     server (`Shares\shieldbase-share\R&D\Mayhem\`).
   - Staging: the `spsql` account aggregated ~40 carbon/alloy/steel/superalloy research
     documents into a `Research\Carbon\{DOC,PDFs,PPT}` + `New Alloy Research` tree on
     rd-01, then deleted it (recovered from spsql's Recycle Bin, ~200 MB).
   - Exfiltration: assessed LIKELY via the Cobalt Strike C2 channel (172.16.4.10[:8080] /
     `squirreldirectory[.]com`); collection/staging is confirmed but an actual off-network
     transfer was not captured (no pcap). Recorded for human judgement.

6. Timeline, scope and anti-forensics.
   - Consolidated UTC timeline below.
   - Scope (confirmed compromised): DC (172.16.4.4), rd-01 (172.16.6.11), rd-02
     (172.16.6.12), file server (172.16.4.5), wkstn-05 (172.16.7.15). Indicated but not
     imaged (tools pushed/executed via c$, or earliest source): BASE-RD-04 (172.16.6.14),
     172.16.4.6, 172.16.6.14. Compromised accounts: spsql, rsydow-a, nromanoff, tdungan
     (and tyler.oslund manipulated).
   - Anti-forensics: file server Security log cleared (1102) by `spsql` 2018-09-06 16:37
     UTC (only confirmed in-window clear; corroborated by the 2.1 MB truncated
     Security.evtx). Tool and staged-data deletion. Name masquerading (csrss.exe, the
     "perfmon" staging dir, "Collect Background Statistics", PerfSvc). DC and RDS event
     logs were NOT cleared. No timestomping/USN tampering was specifically confirmed
     (not exhaustively examined - see Gaps).

---

## Incident timeline (UTC)

| Timestamp (UTC) | Event | Audit Execution Id |
|-----------------|-------|--------------------|
| 2018-08-23 21:36 | `nromanoff` network logon to rd-01 from 172.16.6.14 (BASE-RD-04) - earliest observed attacker activity | b431c00b |
| 2018-08-24 14:40 | `nromanoff` network logon to rd-02 from 172.16.6.14 | b431c00b |
| 2018-08-24 15:35 | BrowsingHistoryView.exe present on rd-01 (recon; Shimcache) | 455f2ca5 |
| 2018-08-24 18:27 | `spsql` accesses rd-01 C$ admin share from 172.16.6.14 (5140) | e71b4484 |
| 2018-08-25 21:03 | `spsql` network logon to rd-02 from 172.16.6.14 | b431c00b |
| 2018-08-28 21:39 | `spsql` RDP (Type 10) 172.16.6.14 -> rd-01 | b431c00b |
| 2018-08-28 22:08-22:43 | `spsql` 4648 explicit-cred spray from rd-01 to file/.4.7/.5.20/rd-02/.6.13/.6.15/.6.16; file-server Cobalt Strike powershell beacon process created (~22:08) | b431c00b, 4ba65cc1 |
| 2018-08-30 21:39-22:14 | p.exe/pa.exe/pb.exe staged in rd-01 C:\Windows\Temp\perfmon (Shimcache) | 455f2ca5 |
| 2018-08-30 22:33 | `spsql` 4648 to 172.16.7.11-7.16 (incl. wkstn-05 = .7.15) | b431c00b |
| 2018-08-31 00:17 | `spsql` RDP (Type 10) rd-01 -> rd-02 | b431c00b |
| 2018-08-31 ~19:59-23:28 | csrss.exe + PerfView.exe pushed to \\172.16.7.15\c$; volrest.exe to \\172.16.6.14\c$ (Shimcache) | 455f2ca5 |
| 2018-08-31 22:16 | file server PowerShell download cradle from hxxp://squirreldirectory[.]com/download/n.ps1; PowerView AD recon loaded | e64417ff |
| 2018-09-05 12:14 | `spsql` runs `ntdsutil` (IFM) on DC -> NTDS.dit dump to C:\temp\Active Directory + C:\temp\registry (driven from rd-01) | 9b35529d, ab87b021, b431c00b |
| 2018-09-05 14:05 | ri.exe pushed/executed to \\172.16.4.5\c$ and \\172.16.4.6\c$ (Shimcache) | 455f2ca5 |
| 2018-09-06 01:37 | `rsydow-a` resets `tyler.oslund` domain password on DC (4724/4738) | c9bcf643, 9b35529d |
| 2018-09-06 16:37 | `spsql` clears file server Security event log (1102) - anti-forensics | 620f36df |
| 2018-09-06 18:57-22:57 | Memory captures taken (dc/rd-01/rd-02/file/wkstn-05) | c9921405 |
| 2018-09-07 01:43-23:14 | Disk images acquired (FTK Imager / F-Response, examiner Clint Barton) | efbeeea1 |

---

## Findings

Each finding: Observation -> Interpretation -> Confidence, with `[audit] execution` ids and
SDK method(s).

F1. Chain of custody / evidence dating. Observation: EWF metadata for all 4 disks =
case 20180905-001, examiner Clint Barton, FTK Imager, acquired 2018-09-07; memory
SystemTimes 2018-09-06 (dc/rd01/rd02/file/wkstn05). Interpretation: 9/10 items are the
2018 incident acquisition. Confidence: HIGH. (exec efbeeea1, c9921405;
EwfInfoAsync / WindowsInfoAsync)

F2. wkstn-01 memory is out-of-incident. Observation: base-wkstn-01-mem.img SystemTime
2021-09-16, normal Win10 process set, empty cmdline/netscan/consoles. Interpretation: not
2018 evidence; wkstn-01 cannot be assessed. Confidence: HIGH. (exec 62bcc75f, 442459ab,
c9921405)

F3. Compromised implant = Cobalt-Strike-style SMB/named-pipe beacon. Observation: rd-01
`p.exe` (SHA256 7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c,
UPX-packed) and file-server `PerfSvc.exe` (SHA256
e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa, a Windows service stub)
both contain the named-pipe token `MSSE-<n>-server`; PerfSvc.exe uses
StartServiceCtrlDispatcher/SetServiceStatus + CreateNamedPipe + rundll32. Memory: file
server powershell spawning 30+ rundll32 children. Interpretation: Cobalt-Strike/Metasploit
SMB beacon (service + packed variants). Confidence: HIGH. (exec 93f4b2fb, 48d19cb2,
421294a8, 4ba65cc1; Sha256Async / YaraToolkit / ExtractStrings / WindowsPsScan)

F4. Tool-staging directory and lateral push. Observation: `C:\Windows\Temp\perfmon\`
toolset on rd-01/rd-02/file; rd-01 Shimcache has UNC exec paths
`\\172.16.4.5\c$`, `\\172.16.4.6\c$`, `\\172.16.6.14\c$`, `\\172.16.7.15\c$`
(...\perfmon\{ri,csrss,volrest,PerfView}.exe). Interpretation: rd-01 was the lateral-push
pivot deploying tools via SMB admin shares. Confidence: HIGH. (exec 455f2ca5;
AnalyzeExecutionEvidenceAsync)

F5. Persistence. Observation: rd-01 scheduled task `\Collect Background Statistics`
(author shieldbase\spsql) -> C:\Windows\Temp\1.bat (deleted); file server PerfSvc.exe
service stub. Interpretation: scheduled-task and service persistence; spsql abused.
Confidence: HIGH. (exec 53856ae8, 328d5ed8, 93f4b2fb; ScheduledTasksAsync /
FindRegistryPersistenceMechanismsAsync)

F6. NTDS.dit credential dump on DC. Observation: ntds.dit (64 MB) + SYSTEM + SECURITY in
C:\temp\Active Directory and C:\temp\registry (+ a copy under C:\Windows\System\Backup);
DC 4688 shows `ntdsutil` run by spsql at 2018-09-05 12:14:50 UTC; matches rd-01 4648 to
the DC at 12:14:36 UTC. Interpretation: full AD database theft via ntdsutil IFM; domain
admin held. Confidence: HIGH (3 artifact classes). (exec ab87b021, 9b35529d, b431c00b;
DetectCredentialDumpingAsync / EvtxECmd / HuntLateralMovement)

F7. Lateral-movement chain via spsql. Observation: spsql Type-10 RDP .6.14->rd-01 (Aug 28)
and rd-01->rd-02 (Aug 31); 4648 spray from rd-01 across the estate and to the DC (Sep 5).
Interpretation: compromised service account used as the pivot credential; order
.6.14 -> rd-01 -> (file/rd-02/workstations) -> DC. Confidence: HIGH. (exec b431c00b,
e71b4484; HuntLateralMovementAsync)

F8. Domain-account manipulation. Observation: DC 4724 password reset of tyler.oslund by
rsydow-a, 2018-09-06 01:37 UTC. Interpretation: rsydow-a is a compromised Domain-Admin-
level account; domain-level account control. Confidence: HIGH. (exec c9bcf643, 9b35529d;
EvtxECmdAsync)

F9. External C2/staging + AD recon. Observation: file server PowerShell 4104 (2018-08-31
22:16 UTC) download cradle to hxxp://squirreldirectory[.]com/download/n.ps1 + gzip stager
+ PowerView.ps1. Interpretation: squirreldirectory[.]com is the external C2/staging
domain; PowerView used for AD reconnaissance. Confidence: HIGH. (exec e64417ff;
AnalyzePowerShellAsync)

F10. Internal C2 beaconing. Observation: rd-01, rd-02, file, wkstn-05 all have TCP to
172.16.4.10:8080 (rd-01 many ESTABLISHED). Interpretation: 172.16.4.10[:8080] is the
common internal C2 endpoint (not imaged). Confidence: HIGH. (exec 0d7fca9a, d4bd410f,
d2c371c3; WindowsNetScanAsync)

F11. Data targeting/staging (Carbonadium). Observation: Carbonadium Development Plan
(rd-02/jpallen), file-server R&D\Mayhem carbon research, and a deleted
spsql Recycle-Bin Research\Carbon staging tree (~40 docs, ~200 MB) on rd-01; spsql/tdungan
Recent-doc LNKs to carbonadium/carbon documents. Interpretation: the proprietary
Carbonadium research was collected and staged for theft. Confidence: HIGH. (exec e87d75f5,
f9de58df; FindFilesAsync)

F12. Anti-forensics - file server log clear. Observation: 1102 Security-log clear by spsql
on base-file 2018-09-06 16:37 UTC; file-server Security.evtx only 2.1 MB. Interpretation:
deliberate event-log clearing on the file server. Confidence: HIGH. (exec 620f36df,
ad6abc1a; DetectLogClearingAsync) [supersedes the erroneous "no in-window clears"
statement in exec 620f36df; see accuracy.md]

F13. wkstn-05 compromised. Observation: 172.16.7.15 beacons to 172.16.4.10:8080; rd-01
pushed csrss.exe to its c$ (Aug 31). Interpretation: workstation compromised in the spread.
Confidence: HIGH. (exec d2c371c3, 455f2ca5)

---

## Gaps / not examined

- wkstn-01: memory capture is a 2021 image (out of incident); no disk image. wkstn-01
  could not be assessed for the 2018 incident. (exec 0dc3dca3)
- BASE-RD-04 (172.16.6.14), the earliest attacker source host, and the internal C2
  172.16.4.10, and hosts 172.16.4.6 were not imaged - so the true initial-access vector
  and patient-zero remain unconfirmed. (exec d5ecce5c)
- No phishing email found in available mailboxes (kellee.espinoza/jpallen OSTs are benign
  lab-generated traffic). (exec ed0b8e4e, 9cfab0d5)
- Exfiltration not directly proven (no packet capture available); inferred from C2.
  (exec 660f460e)
- Process command lines / consoles were unrecoverable from the Server-build memory images
  (file = Win2012R2, rd-02), limiting in-memory command reconstruction there. (exec
  72e7b089)
- Timestomping ($SI vs $FN) and USN-journal tampering were not exhaustively analyzed; the
  masquerading csrss.exe carried a back-dated (2018-06-29) Shimcache time suggestive of
  timestomping but this was not confirmed against $MFT/$FN.
- A full plaso super-timeline / anomaly-engine pass was not required: signature- and
  keyword-driven leads (perfmon toolset, MSSE pipe, squirreldirectory, ntdsutil, 1102)
  were sufficient and directly corroborated.

---

## High-consequence decisions flagged for human judgement (auditReviewRec)

- Malware-family attribution (Cobalt Strike vs Metasploit service payload) - exec 98945333.
- Scope of compromise + domain-admin/privilege level - exec 3ebd76e3.
- Data exfiltration occurred (collection confirmed, transfer inferred) - exec 660f460e.
- System Zero / initial-access vector (under-determined) - exec d5ecce5c.
