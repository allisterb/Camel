# SIFT Tool Coverage by Toolkit

Each toolkit in `Camel.Toolkits` wraps a set of SIFT Workstation command-line tools, registered
in the toolkit's `ToolList` and mapped to a concrete binary in `src/Camel.CLI/appsettings.json`.
The counts below are the registered tools per toolkit (the `ToolList` entries).

| Toolkit | Tools wrapped |
|---|---|
| DiskAnalysis | 29 |
| WindowsAnalysis | 20 |
| PacketAnalysis | 11 |
| UnixTools | 8 |
| Timeline | 6 |
| LinuxAnalysis | 5 |
| Yara | 2 |
| MemoryAnalysis | 1 (Volatility 3, exposing many plugins) |
| **Total** | **82** |

---

## DiskAnalysis — 29 tools
Disk image handling, filesystem analysis, carving, deleted-file recovery, BitLocker.

- **libewf (E01/EWF):** `ewfinfo` (EwfInfo), `ewfverify` (EwfVerify), `ewfmount` (EwfMountRaw)
- **Mounting:** `mount` (EwfMountLoopback, EwfMountNtfs, DDMount), `umount` (Unmount), `mkdir` (MakeMountDir), `fdisk` (ListPartitions)
- **The Sleuth Kit (TSK):** `img_stat` (ImgStat), `mmls` (Mmls), `fsstat` (FsStat), `fls` (Fls), `icat` (Icat), `istat` (Istat), `ffind` (Ffind), `ils` (Ils), `blkls` (Blkls), `tsk_recover` (TskRecover), `mactime` (Mactime), `blkcat` (Blkcat)
- **Carving / recovery:** `bulk_extractor` (BulkExtractor), `photorec` (PhotoRec), `foremost` (Foremost), `scalpel` (Scalpel), `sigfind` (Sigfind), `extundelete` (Extundelete)
- **libbde (BitLocker):** `bdeinfo` (BdeInfo), `bdemount` (BdeMount)

## WindowsAnalysis — 20 tools
Windows host artifacts: registry, event logs, MFT, browser/email, USB.

- **Eric Zimmerman (EZ) tools:** `AmcacheParser`, `AppCompatCacheParser` (shimcache), `MFTECmd` (MFT/UsnJrnl), `JLECmd` (jump lists), `LECmd` (LNK), `WxTCmd` (Win10 timeline), `SBECmd` (shellbags), `RBCmd` (recycle bin), `bstrings` (Bstrings), `EvtxECmd` (event logs), `RECmd` (registry batch), `SQLECmd` (SQLite artifacts)
- **RegRipper:** `rip.pl` (RegRipper)
- **Email / ESE:** `readpst` (ReadPst, libpst), `pffinfo` (Pffinfo, libpff), `esedbexport` (EsedbExport, libesedb), `esedbinfo` (EsedbInfo, libesedb)
- **USB / browser:** `usbdeviceforensics` (UsbDeviceForensics), `hindsight.py` (Hindsight — Chrome), `sqlite3` (Sqlite3 — browser/app DBs)

## PacketAnalysis — 11 tools
Network capture analysis and IDS.

- `tcpdump` (Tcpdump), `tshark` (Tshark), `capinfos` (Capinfos), `editcap` (Editcap), `mergecap` (Mergecap), `tcpflow` (Tcpflow), `tcptrace` (Tcptrace), `ngrep` (Ngrep), `nfdump` (Nfdump), `p0f` (P0f), `suricata` (Suricata)

## UnixTools — 8 tools
Archive extraction, file staging, hashing.

- `bunzip2` (Bunzip2), `unzip` (Unzip), `7z` (SevenZip), `cp` (CopyFile, CopyDir), `md5sum` (MD5Sum), `sha1sum` (SHA1Sum), `sha256sum` (SHA256Sum)

## Timeline — 6 tools
Super-timeline creation and event-log threat hunting.

- **Plaso:** `log2timeline.py` (Log2Timeline), `psort.py` (Psort), `pinfo.py` (Pinfo), `psteal.py` (Psteal), `image_export.py` (ImageExport)
- **Hayabusa:** `hayabusa` (Hayabusa — Sigma over EVTX)

## LinuxAnalysis — 5 tools
Linux host triage from a mounted root.

- `last` (Last), `lastb` (Lastb), `utmpdump` (Utmpdump), `journalctl` (Journalctl), `clamscan` (ClamScan)

## Yara — 2 tools
Pattern-matching malware/IOC scanning.

- `yara` (Scan), `yarac` (Compile)

## MemoryAnalysis — 1 tool
Memory forensics. Registers a single `Volatility3` (`vol`) entry but exposes many Volatility 3
plugins (Windows + Linux `*.*` plugins) as individual toolkit methods.

- `vol` (Volatility3 — Volatility 3 framework)
