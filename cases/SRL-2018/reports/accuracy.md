# Accuracy self-assessment - Case SRL-2018

A candid review of the investigation's accuracy: false positives cleared, a mistake I
caught and corrected, and evidence not obtained. Recorded so a reviewer can weight the
findings.

## Mistakes caught and corrected (hallucination/error)

1. Incorrect "no in-window log clearing" claim (corrected). In exec 620f36df I wrote that
   incident-window Security/System log clears were NOT found on any host. That was wrong:
   I had only queried the DC at that point. The file server's Security log was in fact
   cleared (1102) by `shieldbase\spsql` on 2018-09-06 16:37 UTC. I recorded an
   auditHallucination and a superseding finding in exec 55f3e103 (F12). The error was
   caught within the same session because I then ran DetectLogClearing on rd-02 and file.

2. "p.exe" substring trap (avoided). A prior case note warned that grepping event payloads
   for "p.exe" false-matches rdpclip.exe. I confirmed p.exe execution from the
   WindowsCmdLine `cmd.exe /C c:\windows\temp\perfmon\p.exe` -> p.exe process (full path,
   not a substring), and from the on-disk file + Shimcache, so the p.exe finding is not a
   substring artifact.

## False positives identified and cleared (benign-until-proven-malicious)

- Forensic acquisition activity treated as legitimate, not attacker: examiner account
  `cbarton-a`, forensic station BASE-HUNT (172.16.5.25/5.28/5.50), and the F-Response
  `subject_srv.exe` agent (ports 3262/5682). (exec 0d7fca9a, e71b4484)
- rd-01/rd-02 event-log clears dated 2018-05-04 by WIN10-TEST\Administrator: gold-image /
  sysprep template build, NOT incident anti-forensics. (exec e71b4484, ed0b8e4e ->
  recorded fda476d6)
- DC "suspicious" executables MpSigStub.exe / mpam-*.exe in NetworkService Temp: Windows
  Defender signature updates (weekly cadence). (exec 5189c628)
- Persistence-scan flags for built-in rundll32 scheduled tasks (Application Experience,
  Autochk Proxy, DiskDiagnostic, Sysmain, BFE, PLA), Windows Defender ProgramData tasks,
  and per-SID OneDrive updater tasks: OS baseline, present on all hosts. (exec baa0a8c3)
- Service installs "Microsoft Advanced API 64" (msadvapi2_64.exe), "Lariat", per-user
  svchost services (CDPUserSvc/OneSyncSvc), npcap (npf.sys): SANS lab/range simulation and
  OS baseline, dated May 2018, 0/303 flagged by the workflow. (exec fda476d6)
- ANONYMOUS LOGON type-3 logons from 172.16.6.x in May 2018: lab/printer baseline noise,
  not in the intrusion window. (exec e71b4484)

## Evidence not obtained / not examined (potential blind spots)

- Initial-access vector and patient-zero are unconfirmed: the earliest attacker source
  host BASE-RD-04 (172.16.6.14) and the internal C2 172.16.4.10 were not imaged. The
  System Zero conclusion (BASE-RD-04) is therefore the earliest-visible host, not a proven
  origin. (flagged: exec d5ecce5c)
- No phishing email was found, but mailbox coverage was limited to rd-02
  (kellee.espinoza, jpallen). Other users' mailboxes (e.g. nromanoff, tdungan, on hosts
  not fully searched) were not exhaustively reviewed. (exec ed0b8e4e)
- Exfiltration is inferred from the C2 channel, not proven. No packet capture was
  available; the staged data set's actual transfer off-network was not demonstrated, and
  the external IPs 52.16.55[.]11 / 13.89.220[.]65 were left unconfirmed rather than
  asserted as exfil destinations. (flagged: exec 660f460e)
- Command lines/consoles were unrecoverable from the Server-build memory images (file =
  Win2012R2, rd-02), so in-memory command reconstruction on those hosts is incomplete; the
  rundll32-spawning pattern there is inferred from psscan parentage, not cmdline. (exec
  72e7b089)
- Deleted payload contents not recovered: `1.bat` and `n.ps1` bodies were not carved/
  reconstructed (only their references survive); the exact ntds.dit contents (which hashes/
  krbtgt) were not extracted.
- Kerberoasting (the leading hypothesis for how spsql's password was obtained) was not
  confirmed: 4769 service-ticket analysis on the DC was not performed (the 234 MB DC
  Security.evtx forced targeted, rare-ID-only queries to avoid OOM).
- Timestomping ($SI vs $FN) and USN-journal tampering were not exhaustively analyzed. The
  masquerading csrss.exe carried a back-dated (2018-06-29) Shimcache time that is
  suggestive of timestomping, but this was not confirmed against $MFT.
- wkstn-01 could not be assessed (its only artifact is a 2021 memory capture).
- No full plaso super-timeline / anomaly-engine pass was run; findings rest on signature/
  keyword/artifact analysis. This is adequate here (strong signatures existed) but a
  super-timeline could surface additional low-and-slow activity.

## Confidence summary

- HIGH and well-corroborated (>=2 independent artifact classes): scope of compromise,
  Cobalt-Strike-style implant + tooling, perfmon staging + lateral push, NTDS.dit dump via
  ntdsutil, spsql lateral-movement chain, domain-account manipulation, squirreldirectory
  C2/PowerView recon, internal C2 172.16.4.10, Carbonadium data staging, file-server log
  clearing.
- MEDIUM: exact malware family (Cobalt Strike vs Metasploit), the earliest-source-host
  identification of BASE-RD-04.
- LOW / unproven: initial-access delivery vector, off-network exfiltration, Kerberoasting
  mechanism.
