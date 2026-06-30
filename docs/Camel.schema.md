# Camel JavaScript SDK — Schema Reference

This is the **schema** companion to the Camel JavaScript SDK core reference (`camel-sdk-core` / `Camel.core.md`).
It gives the JSON schema for every parameter and return model type named in the core doc's method signatures.
Use it when you need the exact fields of an object a toolkit or workflow method returns.

Conventions: a `format: "date-time"` string is an ISO-8601 timestamp; an integer field marked "microseconds" is a
POSIX timestamp in microseconds (UTC); `null`/optional fields correspond to C# nullable types. A `$ref` names
another schema in this document. Schemas are grouped under the object whose methods return them; shared toolkit
types are defined once (in the toolkit that owns them) and referenced by name elsewhere.

---

## WorkflowResult (returned by every workflow method)

### WorkflowResult Schema
```json
{
  "type": "object",
  "properties": {
    "IsSuccess": { "type": "boolean", "description": "True if the workflow ran to completion." },
    "Result":    { "description": "The typed payload (type T), or null when IsSuccess is false." },
    "Message":   { "type": "string", "description": "Summary on success, or the explanation on failure." }
  }
}
```

---

## ToolResult (returned by toolkit data methods that can fail)

Every toolkit's data methods return their payload wrapped in a `ToolResult<T>` instead of a bare value, so a
failure carries a reason rather than an opaque `null`. Its members mirror `WorkflowResult<T>`: check `.IsSuccess`
first; read `.Result` on success or `.Message` on failure. An empty `.Result` collection means "ran clean, found
nothing" — not a failure. (A handful of pure-action toolkit methods — mount / dump / extract — return a plain `bool`.)

### ToolResult Schema
```json
{
  "type": "object",
  "properties": {
    "IsSuccess": { "type": "boolean", "description": "True when the operation succeeded and Result is populated." },
    "Result":    { "description": "The typed payload (type T) on success; null when IsSuccess is false." },
    "Message":   { "type": "string", "description": "On failure, why no value was produced (tool not installed vs. command failed); null on success." }
  }
}
```

---

## MemoryAnalysisToolkit

### WindowsInfo Schema
```json
{ "type": "object", "properties": {
  "Variable": { "type": "string" }, "Value": { "type": "string" } } }
```
### WindowsPsList Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "PPID": { "type": "integer" },
  "ImageFileName": { "type": "string" }, "OffsetV": { "type": "integer" },
  "Threads": { "type": "integer" }, "SessionId": { "type": "integer" }, "Wow64": { "type": "boolean" },
  "CreateTime": { "type": "string", "format": "date-time" }, "ExitTime": { "type": "string", "format": "date-time" } } }
```
### WindowsPsScan Schema
```json
{ "type": "object", "description": "Same shape as WindowsPsList.", "properties": {
  "PID": { "type": "integer" }, "PPID": { "type": "integer" }, "ImageFileName": { "type": "string" },
  "OffsetV": { "type": "integer" }, "Threads": { "type": "integer" }, "SessionId": { "type": "integer" },
  "Wow64": { "type": "boolean" },
  "CreateTime": { "type": "string", "format": "date-time" }, "ExitTime": { "type": "string", "format": "date-time" } } }
```
### WindowsPsTree Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "PPID": { "type": "integer" }, "ImageFileName": { "type": "string" },
  "Audit": { "type": "string", "description": "Full on-disk path (audit)." },
  "Path": { "type": "string" }, "Cmd": { "type": "string", "description": "Command line." },
  "OffsetV": { "type": "integer" }, "Threads": { "type": "integer" }, "SessionId": { "type": "integer" },
  "Wow64": { "type": "boolean" },
  "CreateTime": { "type": "string", "format": "date-time" }, "ExitTime": { "type": "string", "format": "date-time" },
  "__children": { "type": "array", "items": { "$ref": "WindowsPsTree" } } } }
```
### WindowsSvcScan Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Display": { "type": "string" }, "State": { "type": "string" },
  "Start": { "type": "string" }, "Type": { "type": "string" }, "PID": { "type": "integer" },
  "Binary": { "type": "string" }, "Binary (Registry)": { "type": "string" }, "Dll": { "type": "string" },
  "Order": { "type": "integer" }, "Offset": { "type": "integer" } } }
```
### WindowsCmdLine Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Args": { "type": "string" } } }
```
### WindowsEnvVars Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" },
  "Variable": { "type": "string" }, "Value": { "type": "string" }, "Block": { "type": "string" } } }
```
### WindowsGetSids Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "SID": { "type": "string" }, "Name": { "type": "string" } } }
```
### WindowsPrivs Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Value": { "type": "integer" },
  "Privilege": { "type": "string" }, "Attributes": { "type": "string" }, "Description": { "type": "string" } } }
```
### WindowsHandles Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Type": { "type": "string" },
  "Name": { "type": "string" }, "GrantedAccess": { "type": "integer" }, "HandleValue": { "type": "integer" },
  "Offset": { "type": "integer" } } }
```
### WindowsDllList Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Name": { "type": "string" },
  "Path": { "type": "string" }, "Base": { "type": "integer" }, "Size": { "type": "integer" },
  "LoadTime": { "type": "string", "format": "date-time" } } }
```
### WindowsModules Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Path": { "type": "string" },
  "Base": { "type": "integer" }, "Size": { "type": "integer" }, "Offset": { "type": "integer" } } }
```
### WindowsModScan Schema
```json
{ "type": "object", "description": "Same shape as WindowsModules.", "properties": {
  "Name": { "type": "string" }, "Path": { "type": "string" },
  "Base": { "type": "integer" }, "Size": { "type": "integer" }, "Offset": { "type": "integer" } } }
```
### WindowsGetServiceSids Schema
```json
{ "type": "object", "properties": { "SID": { "type": "string" }, "Service": { "type": "string" } } }
```
### WindowsNetStat Schema
```json
{ "type": "object", "properties": {
  "Proto": { "type": "string" }, "LocalAddr": { "type": "string" }, "LocalPort": { "type": "integer" },
  "ForeignAddr": { "type": "string" }, "ForeignPort": { "type": "integer" }, "State": { "type": "string" },
  "PID": { "type": "integer" }, "Owner": { "type": "string" }, "Offset": { "type": "integer" },
  "Created": { "type": "string", "format": "date-time" } } }
```
### WindowsNetScan Schema
```json
{ "type": "object", "description": "Same shape as WindowsNetStat.", "properties": {
  "Proto": { "type": "string" }, "LocalAddr": { "type": "string" }, "LocalPort": { "type": "integer" },
  "ForeignAddr": { "type": "string" }, "ForeignPort": { "type": "integer" }, "State": { "type": "string" },
  "PID": { "type": "integer" }, "Owner": { "type": "string" }, "Offset": { "type": "integer" },
  "Created": { "type": "string", "format": "date-time" } } }
```
### WindowsMalFind Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Protection": { "type": "string" },
  "Notes": { "type": "string", "description": "e.g. 'MZ header' marker." }, "Hexdump": { "type": "string" },
  "Disasm": { "type": "string" }, "Tag": { "type": "string" }, "CommitCharge": { "type": "integer" },
  "PrivateMemory": { "type": "integer" }, "Start VPN": { "type": "integer" }, "End VPN": { "type": "integer" } } }
```
### WindowsLdrModules Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Base": { "type": "integer" },
  "InLoad": { "type": "boolean" }, "InInit": { "type": "boolean" }, "InMem": { "type": "boolean" },
  "MappedPath": { "type": "string", "description": "VAD-derived path; empty = loaded outside the Windows API (injection)." } } }
```
### WindowsHollowProcesses Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" },
  "Notes": { "type": "string", "description": "Which hollowing check failed." } } }
```
### WindowsThreads Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "TID": { "type": "integer" },
  "StartAddress": { "type": "integer" }, "StartPath": { "type": "string" },
  "Win32StartAddress": { "type": "integer" }, "Win32StartPath": { "type": "string" }, "Offset": { "type": "integer" },
  "CreateTime": { "type": "string", "format": "date-time" }, "ExitTime": { "type": "string", "format": "date-time" } } }
```
### WindowsSsdt Schema
```json
{ "type": "object", "properties": {
  "Index": { "type": "integer" }, "Address": { "type": "integer" },
  "Module": { "type": "string", "description": "Owning module; non-ntoskrnl/win32k = hook." }, "Symbol": { "type": "string" } } }
```
### WindowsCallbacks Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "string" }, "Callback": { "type": "integer" }, "Module": { "type": "string" },
  "Symbol": { "type": "string" }, "Detail": { "type": "string" } } }
```
### WindowsDriverIrp Schema
```json
{ "type": "object", "properties": {
  "Driver Name": { "type": "string" }, "IRP": { "type": "string" }, "Address": { "type": "integer" },
  "Module": { "type": "string", "description": "Implementing module; non-owning = hook." }, "Symbol": { "type": "string" },
  "Offset": { "type": "integer" } } }
```
### WindowsPsxView Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Name": { "type": "string" }, "Exit Time": { "type": "string" },
  "pslist": { "type": "boolean" }, "psscan": { "type": "boolean" }, "thrdscan": { "type": "boolean" },
  "csrss": { "type": "boolean" }, "Offset(Virtual)": { "type": "integer" } } }
```
### WindowsMutantScan Schema
```json
{ "type": "object", "properties": { "Name": { "type": "string" }, "Offset": { "type": "integer" } } }
```
### WindowsCmdScan Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Application": { "type": "string" },
  "Cmd": { "type": "string", "description": "Typed command line(s)." }, "Data": { "type": "string" },
  "CommandHistory": { "type": "integer" }, "ProcessHandle": { "type": "integer" } } }
```
### WindowsConsoles Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "ConsoleProcess": { "type": "string" },
  "ConsolePid": { "type": "integer" }, "Cmd": { "type": "string" },
  "Data": { "type": "string", "description": "Screen-buffer output (commands + program output)." } } }
```
### WindowsFileScan Schema
```json
{ "type": "object", "properties": { "Name": { "type": "string" }, "Offset": { "type": "integer" } } }
```
### WindowsVadInfo Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Protection": { "type": "string" },
  "Tag": { "type": "string" }, "File": { "type": "string" }, "Start VPN": { "type": "integer" },
  "End VPN": { "type": "integer" }, "CommitCharge": { "type": "integer" }, "PrivateMemory": { "type": "integer" },
  "Parent": { "type": "integer" }, "Offset": { "type": "integer" } } }
```
### WindowsRegistryHiveList Schema
```json
{ "type": "object", "properties": {
  "FileFullPath": { "type": "string" }, "Offset": { "type": "integer" } } }
```
### WindowsRegistryPrintKey Schema
```json
{ "type": "object", "properties": {
  "Key": { "type": "string" }, "Name": { "type": "string" }, "Type": { "type": "string" },
  "Data": { "type": "string" }, "Volatile": { "type": "boolean" }, "Hive Offset": { "type": "integer" },
  "Last Write Time": { "type": "string", "format": "date-time" } } }
```
### WindowsRegistryUserAssist Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Count": { "type": "integer" },
  "Focus Count": { "type": "integer" }, "Time Focused": { "type": "string" },
  "Last Updated": { "type": "string", "format": "date-time" }, "Hive Name": { "type": "string" }, "Type": { "type": "string" } } }
```
### WindowsShimcacheMem Schema
```json
{ "type": "object", "properties": {
  "File Path": { "type": "string" }, "Exec Flag": { "type": "string" }, "File Size": { "type": "integer" },
  "Last Modified": { "type": "string", "format": "date-time" }, "Last Update": { "type": "string", "format": "date-time" },
  "Order": { "type": "integer" } } }
```
### WindowsHashdump Schema
```json
{ "type": "object", "properties": {
  "User": { "type": "string" }, "rid": { "type": "integer" }, "lmhash": { "type": "string" }, "nthash": { "type": "string" } } }
```
### WindowsLsadump Schema
```json
{ "type": "object", "properties": {
  "Key": { "type": "string" }, "Secret": { "type": "string", "description": "Space-separated hex bytes." },
  "Hex": { "type": "string" } } }
```
### WindowsCachedump Schema
```json
{ "type": "object", "properties": {
  "Username": { "type": "string" }, "Domain": { "type": "string" }, "Domain name": { "type": "string" }, "Hash": { "type": "string" } } }
```
### WindowsSkeletonKeyCheck Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Skeleton Key Found": { "type": "boolean" },
  "rc4HmacInitialize": { "type": "integer" }, "rc4HmacDecrypt": { "type": "integer" } } }
```
### WindowsProcessGhosting Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Path": { "type": "string" },
  "DeletePending": { "type": "integer" }, "FILE_OBJECT": { "type": "integer" } } }
```
### WindowsVerInfo Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Name": { "type": "string" },
  "Product": { "type": "string" }, "Major": { "type": "integer" }, "Minor": { "type": "integer" },
  "Build": { "type": "integer" }, "Base": { "type": "integer" } } }
```
### WindowsVadYaraScan Schema
```json
{ "type": "object", "properties": {
  "Rule": { "type": "string" }, "PID": { "type": "integer" }, "Process": { "type": "string" },
  "Offset": { "type": "integer" }, "Component": { "type": "string" }, "Value": { "type": "string" } } }
```

---

## DiskAnalysisToolkit

### EwfInfo Schema
```json
{ "type": "object", "properties": {
  "CaseNumber": { "type": "string" }, "Description": { "type": "string" }, "ExaminerName": { "type": "string" },
  "EvidenceNumber": { "type": "string" }, "AcquisitionDate": { "type": "string" }, "OperatingSystemUsed": { "type": "string" },
  "FileFormat": { "type": "string" }, "MediaType": { "type": "string" }, "MediaSize": { "type": "string" },
  "IsPhysical": { "type": "boolean" }, "BytesPerSector": { "type": "integer" }, "NumberOfSectors": { "type": "integer" },
  "MD5": { "type": "string" }, "SHA1": { "type": "string" } } }
```
### EwfVerify Schema
```json
{ "type": "object", "properties": {
  "Success": { "type": "boolean" }, "Result": { "type": "string" },
  "StoredMD5": { "type": "string" }, "CalculatedMD5": { "type": "string" },
  "StoredSHA1": { "type": "string" }, "CalculatedSHA1": { "type": "string" } } }
```
### ImgStat Schema
```json
{ "type": "object", "properties": {
  "ImageType": { "type": "string" }, "SizeOfData": { "type": "integer" }, "SectorSize": { "type": "integer" }, "MD5": { "type": "string" } } }
```
### MmlsEntry Schema
```json
{ "type": "object", "properties": {
  "Index": { "type": "integer" }, "Slot": { "type": "string" },
  "Start": { "type": "integer", "description": "Start sector — the offset to pass to mount methods." },
  "End": { "type": "integer" }, "Length": { "type": "integer" }, "Description": { "type": "string" } } }
```
### PartitionInfo Schema
```json
{ "type": "object", "properties": {
  "DeviceName": { "type": "string" }, "Boot": { "type": "boolean" },
  "Start": { "type": "integer", "description": "Start sector." }, "End": { "type": "integer" },
  "Sectors": { "type": "integer" }, "Size": { "type": "string" }, "Id": { "type": "string" }, "Type": { "type": "string" } } }
```
### FsStat Schema
```json
{ "type": "object", "properties": {
  "FileSystemType": { "type": "string" }, "VolumeSerialNumber": { "type": "string" }, "OemName": { "type": "string" },
  "Version": { "type": "string" }, "SectorSize": { "type": "integer" }, "ClusterSize": { "type": "integer" },
  "RootDirectory": { "type": "integer" }, "Properties": { "type": "object", "description": "Full label→value map." } } }
```
### FlsEntry Schema
```json
{ "type": "object", "properties": {
  "NameType": { "type": "string", "description": "e.g. 'r/r', 'd/d'." }, "Deleted": { "type": "boolean" },
  "Reallocated": { "type": "boolean" }, "Inode": { "type": "string" }, "Name": { "type": "string" } } }
```
### Istat Schema
```json
{ "type": "object", "properties": {
  "Entry": { "type": "integer" }, "Sequence": { "type": "integer" }, "Allocated": { "type": "boolean" },
  "Links": { "type": "integer" }, "Created": { "type": "string", "format": "date-time" },
  "FileModified": { "type": "string", "format": "date-time" }, "MftModified": { "type": "string", "format": "date-time" },
  "Accessed": { "type": "string", "format": "date-time" }, "RawText": { "type": "string" } } }
```
### IlsEntry Schema
```json
{ "type": "object", "properties": {
  "StIno": { "type": "integer" }, "StAlloc": { "type": "string" }, "StUid": { "type": "integer" }, "StGid": { "type": "integer" },
  "StMtime": { "type": "integer" }, "StAtime": { "type": "integer" }, "StCtime": { "type": "integer" }, "StCrtime": { "type": "integer" },
  "StMode": { "type": "string" }, "StNlink": { "type": "integer" }, "StSize": { "type": "integer" } } }
```
### FsFile Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Size": { "type": "integer", "description": "Bytes." } } }
```
### MactimeEntry Schema
```json
{ "type": "object", "properties": {
  "Date": { "type": "string" }, "Size": { "type": "integer" },
  "ActivityType": { "type": "string", "description": "MACB letters." }, "Mode": { "type": "string" },
  "Uid": { "type": "integer" }, "Gid": { "type": "integer" }, "Meta": { "type": "string" }, "FileName": { "type": "string" } } }
```

---

## WindowsAnalysisToolkit

### LolbasReference Schema
```json
{ "type": "object",
  "description": "Queryable index (not plain data). Methods: IsLolbin(name) -> bool; CanonicalPaths(name) -> string[]; IsCanonicalPath(name, programPath) -> bool. Property: Count -> int.",
  "properties": { "Count": { "type": "integer" } } }
```
### MFTEntry Schema
```json
{ "type": "object", "properties": {
  "EntryNumber": { "type": "integer" }, "SequenceNumber": { "type": "integer" },
  "ParentEntryNumber": { "type": "integer" }, "InUse": { "type": "boolean" },
  "ParentPath": { "type": "string" }, "FileName": { "type": "string" }, "Extension": { "type": "string" },
  "IsDirectory": { "type": "boolean" }, "HasAds": { "type": "boolean" }, "IsAds": { "type": "boolean" },
  "FileSize": { "type": "integer" },
  "Created0x10": { "type": "string", "format": "date-time", "description": "$SI creation time." },
  "LastModified0x10": { "type": "string", "format": "date-time" },
  "LastRecordChange0x10": { "type": "string", "format": "date-time" },
  "LastAccess0x10": { "type": "string", "format": "date-time" },
  "Timestomped": { "type": "boolean", "description": "$SI predates $FN (backdating tell)." },
  "uSecZeros": { "type": "boolean", "description": "Sub-second precision zeroed." } } }
```
### UsnJournalEntry Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Extension": { "type": "string" },
  "EntryNumber": { "type": "integer" }, "ParentEntryNumber": { "type": "integer" }, "UpdateSequenceNumber": { "type": "integer" },
  "UpdateTimestamp": { "type": "string", "format": "date-time" },
  "UpdateReasons": { "type": "string", "description": "Pipe-joined reasons, e.g. 'FileCreate|Close'." } } }
```
### MFTECmdResult Schema
```json
{ "type": "object", "properties": {
  "OutputDirectory": { "type": "string" }, "OutputFile": { "type": "string" },
  "FileRecords": { "type": "integer" }, "FreeRecords": { "type": "integer" } } }
```
### LnkFile Schema
```json
{ "type": "object", "properties": {
  "SourceFile": { "type": "string" }, "LocalPath": { "type": "string" }, "RelativePath": { "type": "string" },
  "WorkingDirectory": { "type": "string" }, "Arguments": { "type": "string" }, "MachineID": { "type": "string" },
  "FileSize": { "type": "integer" },
  "TargetCreated": { "type": "string", "format": "date-time" }, "TargetModified": { "type": "string", "format": "date-time" },
  "TargetAccessed": { "type": "string", "format": "date-time" } } }
```
### ShellBag Schema
```json
{ "type": "object", "properties": {
  "BagPath": { "type": "string" }, "AbsolutePath": { "type": "string" }, "Value": { "type": "string" },
  "ShellType": { "type": "string" }, "Slot": { "type": "integer" }, "NodeSlot": { "type": "integer" },
  "ChildBags": { "type": "integer" },
  "FirstInteracted": { "type": "string", "format": "date-time" }, "LastInteracted": { "type": "string", "format": "date-time" },
  "LastWriteTime": { "type": "string", "format": "date-time" } } }
```
### SBECmdCsvResult Schema
```json
{ "type": "object", "properties": {
  "OutputDirectory": { "type": "string" }, "CsvFiles": { "type": "array", "items": { "type": "string" } },
  "TotalShellBags": { "type": "integer" } } }
```
### ShimcacheEntry Schema
```json
{ "type": "object", "properties": {
  "ControlSet": { "type": "integer" }, "CacheEntryPosition": { "type": "integer" }, "Path": { "type": "string" },
  "LastModifiedTimeUTC": { "type": "string", "format": "date-time" },
  "Executed": { "type": "string" }, "Duplicate": { "type": "boolean" }, "SourceFile": { "type": "string" } } }
```
### AmcacheEntry Schema
```json
{ "type": "object", "properties": {
  "FullPath": { "type": "string" }, "Name": { "type": "string" }, "SHA1": { "type": "string" },
  "FileKeyLastWriteTimestamp": { "type": "string", "format": "date-time" },
  "LinkDate": { "type": "string", "format": "date-time", "description": "PE compile time." },
  "ApplicationName": { "type": "string" }, "ProductName": { "type": "string" }, "Size": { "type": "integer" },
  "Version": { "type": "string" }, "IsOsComponent": { "type": "boolean" }, "IsPeFile": { "type": "boolean" },
  "FileExtension": { "type": "string" } } }
```
### RecycleBinEntry Schema
```json
{ "type": "object", "properties": {
  "SourceName": { "type": "string" }, "FileName": { "type": "string" }, "FileType": { "type": "string" },
  "FileSize": { "type": "integer" }, "DeletedOn": { "type": "string", "format": "date-time" } } }
```
### JumpListEntry Schema
```json
{ "type": "object", "properties": {
  "AppId": { "type": "string" }, "AppIdDescription": { "type": "string" }, "Path": { "type": "string" },
  "EntryNumber": { "type": "integer" }, "InteractionCount": { "type": "integer" }, "FileSize": { "type": "integer" },
  "CreationTime": { "type": "string", "format": "date-time" }, "LastModified": { "type": "string", "format": "date-time" },
  "Arguments": { "type": "string" }, "WorkingDirectory": { "type": "string" }, "MachineID": { "type": "string" } } }
```
### TimelineActivity Schema
```json
{ "type": "object", "properties": {
  "Id": { "type": "string" }, "ActivityType": { "type": "string" }, "Executable": { "type": "string" },
  "DisplayText": { "type": "string" }, "ContentInfo": { "type": "string" }, "Payload": { "type": "string" },
  "StartTime": { "type": "string", "format": "date-time" }, "EndTime": { "type": "string", "format": "date-time" },
  "LastModifiedTime": { "type": "string", "format": "date-time" }, "AppId": { "type": "string" } } }
```
### RegistryEntry Schema
```json
{ "type": "object", "properties": {
  "HivePath": { "type": "string" }, "HiveType": { "type": "string" }, "Description": { "type": "string" },
  "Category": { "type": "string" }, "KeyPath": { "type": "string" }, "ValueName": { "type": "string" },
  "ValueType": { "type": "string" }, "ValueData": { "type": "string" }, "ValueData2": { "type": "string" },
  "ValueData3": { "type": "string" }, "Comment": { "type": "string" }, "Recursive": { "type": "boolean" },
  "Deleted": { "type": "boolean" }, "LastWriteTimestamp": { "type": "string", "format": "date-time" } } }
```
### EventLogEntry Schema
```json
{ "type": "object", "properties": {
  "RecordNumber": { "type": "integer" }, "EventId": { "type": "integer" },
  "TimeCreated": { "type": "string", "format": "date-time" }, "Level": { "type": "string" },
  "Provider": { "type": "string" }, "Channel": { "type": "string" }, "Computer": { "type": "string" },
  "UserId": { "type": "string" }, "ProcessId": { "type": "integer" }, "ThreadId": { "type": "integer" },
  "Keywords": { "type": "string" }, "MapDescription": { "type": "string" },
  "Payload": { "type": "string", "description": "Raw event-field JSON ({\"EventData\":{\"Data\":[{\"@Name\":..,\"#text\":..}]}})." },
  "SourceFile": { "type": "string" } } }
```
### EvtxECmdCsvResult Schema
```json
{ "type": "object", "properties": {
  "OutputDirectory": { "type": "string" }, "OutputFile": { "type": "string" },
  "RecordsIncluded": { "type": "integer" }, "Errors": { "type": "integer" }, "EventsDropped": { "type": "integer" } } }
```
### RegRipperResult Schema
```json
{ "type": "object", "properties": {
  "Plugin": { "type": "string" }, "Hive": { "type": "string" }, "Version": { "type": "string" },
  "Output": { "type": "string", "description": "Full plugin text output." },
  "Lines": { "type": "array", "items": { "type": "string" }, "description": "Output split into lines (parse per plugin)." } } }
```
### ScheduledTaskEntry Schema
```json
{ "type": "object", "properties": {
  "TaskFile": { "type": "string" }, "Uri": { "type": "string" }, "Author": { "type": "string" },
  "Command": { "type": "string", "description": "First Exec action's program (null for COM-handler tasks)." },
  "Arguments": { "type": "string" }, "WorkingDirectory": { "type": "string" } } }
```
### WmiSubscriptions Schema
```json
{ "type": "object", "properties": {
  "Consumers": { "type": "array", "items": { "$ref": "WmiConsumer" } },
  "Filters": { "type": "array", "items": { "type": "string" } },
  "Bindings": { "type": "array", "items": { "$ref": "WmiBinding" } } } }
```
### WmiConsumer Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "string", "description": "e.g. CommandLineEventConsumer." }, "Name": { "type": "string" },
  "Command": { "type": "string", "description": "Recovered action command line / script." } } }
```
### WmiBinding Schema
```json
{ "type": "object", "properties": { "ConsumerName": { "type": "string" }, "FilterName": { "type": "string" } } }
```

---

## TimelineAnalysisToolkit

### TimelineEvent Schema
```json
{ "type": "object", "properties": {
  "Timestamp": { "type": "integer", "description": "POSIX microseconds (UTC)." },
  "TimestampDesc": { "type": "string", "description": "MACB role / timestamp description." },
  "DataType": { "type": "string", "description": "Plaso data_type, e.g. 'windows:evtx:record'." },
  "Parser": { "type": "string" }, "DisplayName": { "type": "string" }, "Filename": { "type": "string" },
  "Inode": { "type": "string" }, "Message": { "type": "string", "description": "Rendered human-readable text." },
  "Sha256Hash": { "type": "string" }, "Md5Hash": { "type": "string" },
  "Tag": { "type": "object", "properties": { "Labels": { "type": "array", "items": { "type": "string" } } } } } }
```
### PlasoInfo Schema
```json
{ "type": "object", "properties": {
  "ParserCounts": { "type": "object", "description": "Per-parser event counts (incl. a 'total' entry)." },
  "TotalEvents": { "type": "integer" } } }
```
### HayabusaAlert Schema
```json
{ "type": "object", "properties": {
  "Timestamp": { "type": "string" }, "RuleTitle": { "type": "string" }, "Level": { "type": "string" },
  "Computer": { "type": "string" }, "Channel": { "type": "string" }, "EventID": { "type": "integer" },
  "RecordID": { "type": "integer" }, "RuleID": { "type": "string" } } }
```
### ComputerMetric Schema
```json
{ "type": "object", "properties": {
  "Computer": { "type": "string" }, "Events": { "type": "integer" }, "OsInformation": { "type": "string" },
  "UpTime": { "type": "string" }, "Timezone": { "type": "string" } } }
```
### EidMetric Schema
```json
{ "type": "object", "properties": {
  "EventId": { "type": "integer" }, "Channel": { "type": "string" }, "Event": { "type": "string" },
  "Total": { "type": "integer" }, "Percent": { "type": "string" } } }
```
### LogMetric Schema
```json
{ "type": "object", "properties": {
  "Filename": { "type": "string" }, "Computers": { "type": "string" }, "Events": { "type": "integer" },
  "Channels": { "type": "string" }, "Providers": { "type": "string" }, "Size": { "type": "string" },
  "FirstTimestamp": { "type": "string" }, "LastTimestamp": { "type": "string" } } }
```
### LogonSummaryEntry Schema
```json
{ "type": "object", "properties": {
  "Successful": { "type": "boolean" }, "Count": { "type": "integer" }, "Event": { "type": "string" },
  "TargetAccount": { "type": "string" }, "TargetComputer": { "type": "string" }, "LogonType": { "type": "string" },
  "SourceAccount": { "type": "string" }, "SourceComputer": { "type": "string" }, "SourceIpAddress": { "type": "string" } } }
```

---

## YaraToolkit

### YaraOptions Schema
```json
{ "type": "object", "properties": {
  "Recurse": { "type": "boolean", "description": "-r recursive directory scan." },
  "PrintStrings": { "type": "boolean" }, "PrintMeta": { "type": "boolean" }, "PrintTags": { "type": "boolean" },
  "PrintNamespace": { "type": "boolean" }, "PrintNonMatching": { "type": "boolean" }, "FastScan": { "type": "boolean" },
  "Compiled": { "type": "boolean", "description": "Rules file is yarac-compiled." }, "NoFollowSymlinks": { "type": "boolean" },
  "ScanList": { "type": "boolean" }, "Threads": { "type": "integer" },
  "Timeout": { "type": "integer", "description": "Skip a file after N seconds." }, "MaxRules": { "type": "integer" },
  "Tag": { "type": "string" }, "Define": { "type": "object", "description": "External var name→value." } } }
```
### YaraMatch Schema
```json
{ "type": "object", "properties": {
  "Rule": { "type": "string" }, "Namespace": { "type": "string" }, "Target": { "type": "string", "description": "Path that matched." },
  "Tags": { "type": "array", "items": { "type": "string" } }, "Meta": { "type": "string" },
  "MatchedStrings": { "type": "array", "items": { "type": "string" }, "description": "Populated when PrintStrings is set." } } }
```

---

## UnixToolsToolkit

### DecompressResult Schema
```json
{ "type": "object", "properties": {
  "Source": { "type": "string", "description": "The archive that was decompressed/extracted." },
  "OutputPath": { "type": "string", "description": "Decompressed file (Bunzip2) or destination directory (Unzip)." },
  "Files": { "type": "array", "items": { "$ref": "ExtractedFile" }, "description": "Files produced by the operation." },
  "TotalBytes": { "type": "integer", "description": "Sum of the produced files' sizes." } } }
```
### CopyResult Schema
```json
{ "type": "object", "properties": {
  "Source": { "type": "string", "description": "The file or directory that was copied." },
  "Destination": { "type": "string", "description": "Path the copy landed at (file for CopyFile, directory for CopyDir)." },
  "Files": { "type": "array", "items": { "$ref": "ExtractedFile" }, "description": "Files written by the copy." },
  "TotalBytes": { "type": "integer", "description": "Sum of the copied files' sizes." },
  "Verified": { "type": ["boolean", "null"], "description": "SHA-256 source-vs-copy result; null when verify was not requested." },
  "Mismatches": { "type": "array", "items": { "type": "string" }, "description": "Destination paths whose hash didn't match (empty on success)." } } }
```
### ExtractedFile Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Size": { "type": "integer", "description": "File size in bytes." } } }
```

---

## AnomalyDetectionToolkit

### TriageReport Schema
```json
{ "type": "object", "properties": {
  "Shortlist": { "type": "array", "items": { "$ref": "TriageItem" } },
  "TotalEvents": { "type": "integer" },
  "Candidates": { "type": "integer", "description": "Distinct episodes any detector flagged." },
  "CompressionRatio": { "type": "number", "description": "Shortlist.length / TotalEvents." } } }
```
### TriageItem Schema
```json
{ "type": "object", "properties": {
  "EventIndex": { "type": "integer" }, "Ts": { "type": "integer", "description": "POSIX microseconds (UTC)." },
  "Time": { "type": "string", "format": "date-time" },
  "Token": { "type": "string", "description": "Behavioural event-type token, e.g. 'evtx:1102'." },
  "TotalBits": { "type": "number", "description": "Summed surprisal across detectors that fired." },
  "Count": { "type": "integer", "description": "Events collapsed into this episode." },
  "MemberIndices": { "type": "array", "items": { "type": "integer" } },
  "Findings": { "type": "array", "items": { "$ref": "Finding" } } } }
```
### Finding Schema
```json
{ "type": "object", "properties": {
  "EventIndex": { "type": "integer" }, "Ts": { "type": "integer" }, "Token": { "type": "string" },
  "Bits": { "type": "number" },
  "Detector": { "type": "string", "enum": ["rare-type","rare-transition","timing-burst","timing-beacon","content"] },
  "Reason": { "type": "string", "description": "Human-readable why-flagged explanation." } } }
```
### CanonicalEvent Schema
```json
{ "type": "object",
  "description": "Normalized event form (input to Triage / output of canonicalization).",
  "properties": {
    "Ts": { "type": "integer", "description": "POSIX microseconds (UTC)." },
    "DataType": { "type": "string" },
    "Source": { "type": "string", "enum": ["Other","FileSystem","Registry","EventLog","WebHistory","Lnk","Prefetch","Log"] },
    "Macb": { "type": "string", "description": "Flags: Modified/Accessed/Changed/Birth." },
    "Location": { "type": "string", "enum": ["Unknown","System32","SysWow64","WindowsOther","ProgramFiles","ProgramData","UsersProfile","AppData","Temp","Recycle","Network","Root","Other"] },
    "Ext": { "type": "string" }, "EventId": { "type": "integer" },
    "MsgLength": { "type": "integer" }, "BadWordCount": { "type": "integer" },
    "Reg": { "type": "string", "enum": ["None","Run","Service","Shimcache","Amcache","UserAssist","Bam","MountPoints","UsbStor","Network","Bagmru","Mru","TaskCache","Winlogon","Other"] },
    "DtPrev": { "type": "number", "description": "ln(1 + Δseconds) since previous event." },
    "HourOfDay": { "type": "integer" },
    "Labels": { "type": "array", "items": { "type": "string" } } } }
```

---

## DiskAnalysisWorkflow

### EwfImageMount Schema
```json
{ "type": "object", "properties": {
  "MountDir": { "type": "string" }, "RawDevice": { "type": "string", "description": "<MountDir>/ewf1." },
  "Info": { "$ref": "EwfInfo" }, "PartitionTable": { "type": "array", "items": { "$ref": "MmlsEntry" } } } }
```
### FileSystemMount Schema
```json
{ "type": "object", "properties": {
  "MountDir": { "type": "string" }, "RawDevice": { "type": "string" }, "Offset": { "type": "integer" },
  "Info": { "$ref": "FsStat" } } }
```
### BitLockerInfo Schema
```json
{ "type": "object", "properties": {
  "IsBitLockerVolume": { "type": "boolean", "description": "True when a BDE volume was recognised at the offset." },
  "EncryptionMethod": { "type": ["string","null"], "description": "e.g. 'AES-CBC 128-bit', 'AES-XTS 256-bit'." },
  "VolumeIdentifier": { "type": ["string","null"] }, "CreationTime": { "type": ["string","null"], "description": "UTC." },
  "Description": { "type": ["string","null"] },
  "KeyProtectors": { "type": "array", "items": { "$ref": "BitLockerKeyProtector" } },
  "RawText": { "type": "string", "description": "Full unparsed bdeinfo output (authoritative)." } } }
```
### BitLockerKeyProtector Schema
```json
{ "type": "object", "properties": {
  "Index": { "type": "integer", "description": "Protector ordinal (0-based)." },
  "Identifier": { "type": ["string","null"] },
  "Type": { "type": "string", "description": "TPM | TPM and PIN | Recovery password | Password | Startup key | External key." } } }
```
### BitLockerVolumeMount Schema
```json
{ "type": "object", "properties": {
  "BdeMountDir": { "type": "string", "description": "bdemount FUSE dir holding the decrypted bde1 device." },
  "DecryptedDevice": { "type": "string", "description": "<BdeMountDir>/bde1 - pass to the TSK tools with no offset." },
  "FilesystemMountDir": { "type": ["string","null"], "description": "Where the cleartext volume is loop-mounted, or null." },
  "Info": { "$ref": "BitLockerInfo" }, "FilesystemInfo": { "anyOf": [ { "$ref": "FsStat" }, { "type": "null" } ] } } }
```
### ImageVerification Schema
```json
{ "type": "object", "properties": {
  "Info": { "$ref": "EwfInfo" }, "Verification": { "$ref": "EwfVerify" },
  "IntegrityVerified": { "type": "boolean", "description": "True only when calculated hash == acquisition hash." } } }
```
### FilesystemTimeline Schema
```json
{ "type": "object", "properties": {
  "BodyfilePath": { "type": "string" }, "Entries": { "type": "array", "items": { "$ref": "MactimeEntry" } } } }
```
### FileRecovery Schema
```json
{ "type": "object", "properties": {
  "OutputDir": { "type": "string" }, "FilesRecovered": { "type": "integer" }, "IncludedDeleted": { "type": "boolean" } } }
```

---

## MemoryAnalysisWorkflow

### HiddenProcessReport Schema
```json
{ "type": "object", "properties": {
  "HiddenProcesses": { "type": "array", "items": { "$ref": "WindowsPsScan" }, "description": "Running but unlinked (DKOM)." },
  "ExitedProcesses": { "type": "array", "items": { "$ref": "WindowsPsScan" } },
  "PsListCount": { "type": "integer" }, "PsScanCount": { "type": "integer" } } }
```
### SuspiciousServiceReport Schema
```json
{ "type": "object", "properties": {
  "SuspiciousServices": { "type": "array", "items": { "$ref": "WindowsSvcScan" } }, "TotalServices": { "type": "integer" } } }
```
### AnomalousMemoryReport Schema
```json
{ "type": "object", "properties": {
  "MzHeaderRegions": { "type": "array", "items": { "$ref": "WindowsMalFind" }, "description": "Injected PE images (hollowing)." },
  "RwxRegions": { "type": "array", "items": { "$ref": "WindowsMalFind" }, "description": "RWX (shellcode)." },
  "SuspectRegions": { "type": "array", "items": { "$ref": "WindowsMalFind" }, "description": "All malfind hits." },
  "DumpedExecutables": { "type": "array", "items": { "type": "string" } },
  "DumpedProcessMemory": { "type": "array", "items": { "type": "string" } },
  "ExtractedStrings": { "type": "array", "items": { "type": "string" } } } }
```
### RemoteIpReport Schema
```json
{ "type": "object", "properties": {
  "RemoteIPs": { "type": "array", "items": { "type": "string" }, "description": "De-duplicated routable foreign IPs." },
  "Connections": { "type": "array", "items": { "$ref": "WindowsNetScan" } } } }
```
### CredentialReport Schema
```json
{ "type": "object", "properties": {
  "LocalHashes": { "type": "array", "items": { "$ref": "WindowsHashdump" } },
  "LsaSecrets": { "type": "array", "items": { "$ref": "LsaSecret" } },
  "CachedCredentials": { "type": "array", "items": { "$ref": "WindowsCachedump" } },
  "PlaintextSecrets": { "type": "array", "items": { "$ref": "LsaSecret" }, "description": "Secrets that decoded to plaintext." } } }
```
### LsaSecret Schema
```json
{ "type": "object", "properties": {
  "Key": { "type": "string" }, "Hex": { "type": "string" }, "DecodedText": { "type": "string", "description": "UTF-16 plaintext when printable, else null." } } }
```
### MemoryTimeline Schema
```json
{ "type": "object", "properties": { "TimelinePath": { "type": "string" }, "BodyfilePath": { "type": "string" } } }
```
### CodeInjectionReport Schema
```json
{ "type": "object", "properties": {
  "UnlinkedDlls": { "type": "array", "items": { "$ref": "WindowsLdrModules" } },
  "HollowedProcesses": { "type": "array", "items": { "$ref": "WindowsHollowProcesses" } },
  "AnomalousRegions": { "$ref": "AnomalousMemoryReport" },
  "SuspectPids": { "type": "array", "description": "Distinct flagged PIDs by signal count.",
    "items": { "type": "object", "properties": { "Pid": { "type": "integer" }, "Process": { "type": "string" }, "SignalCount": { "type": "integer" } } } } } }
```
### KernelRootkitReport Schema
```json
{ "type": "object", "properties": {
  "Hooks": { "type": "array", "items": { "$ref": "KernelHook" } },
  "SsdtScanned": { "type": "integer" }, "CallbacksScanned": { "type": "integer" }, "DriverIrpScanned": { "type": "integer" },
  "ForeignModules": { "type": "array",
    "items": { "type": "object", "properties": { "Module": { "type": "string" }, "HookCount": { "type": "integer" } } } } } }
```
### KernelHook Schema
```json
{ "type": "object", "properties": {
  "HookSurface": { "type": "string", "enum": ["SSDT","Callback","IRP"] }, "Target": { "type": "string" },
  "Module": { "type": "string" }, "Symbol": { "type": "string" }, "Address": { "type": "integer" } } }
```
### CrossViewHiddenProcessReport Schema
```json
{ "type": "object", "properties": {
  "AllSightings": { "type": "array", "items": { "$ref": "HiddenProcessSighting" } },
  "HiddenSightings": { "type": "array", "items": { "$ref": "HiddenProcessSighting" } } } }
```
### HiddenProcessSighting Schema
```json
{ "type": "object", "properties": {
  "Pid": { "type": "integer" }, "Name": { "type": "string" }, "ExitTime": { "type": "string" },
  "PsList": { "type": "boolean" }, "PsScan": { "type": "boolean" }, "ThrdScan": { "type": "boolean" }, "Csrss": { "type": "boolean" },
  "HasExited": { "type": "boolean" },
  "SeenBy": { "type": "array", "items": { "type": "string" } }, "MissedBy": { "type": "array", "items": { "type": "string" } } } }
```
### ConsoleHistoryReport Schema
```json
{ "type": "object", "properties": {
  "ConsoleSessions": { "type": "array", "items": { "$ref": "ConsoleSession" } },
  "TypedCommands": { "type": "array", "items": { "$ref": "TypedCommand" } } } }
```
### ConsoleSession Schema
```json
{ "type": "object", "properties": {
  "Pid": { "type": "integer" }, "Process": { "type": "string" }, "Application": { "type": "string" },
  "TypedCommands": { "type": "array", "items": { "type": "string" } }, "ScreenOutput": { "type": "string" } } }
```
### TypedCommand Schema
```json
{ "type": "object", "properties": { "Pid": { "type": "integer" }, "Process": { "type": "string" }, "Command": { "type": "string" } } }
```
### MemoryYaraReport Schema
```json
{ "type": "object", "properties": {
  "Matches": { "type": "array", "items": { "$ref": "WindowsVadYaraScan" } }, "RulesFile": { "type": "string" },
  "MatchesByRule": { "type": "array", "items": { "type": "object", "properties": { "Rule": { "type": "string" }, "Count": { "type": "integer" } } } },
  "MatchesByProcess": { "type": "array", "items": { "type": "object", "properties": { "Pid": { "type": "integer" }, "Process": { "type": "string" }, "Count": { "type": "integer" } } } } } }
```
### SkeletonKeyReport Schema
```json
{ "type": "object", "properties": {
  "Findings": { "type": "array", "items": { "$ref": "WindowsSkeletonKeyCheck" } },
  "IsCompromised": { "type": "boolean" } } }
```
### ProcessAnomaly Schema
```json
{ "type": "object", "properties": {
  "Pid": { "type": "integer" }, "Name": { "type": "string" }, "ParentPid": { "type": "integer" }, "ParentName": { "type": "string" },
  "Path": { "type": "string" }, "CommandLine": { "type": "string" },
  "Categories": { "type": "array", "items": { "type": "string" }, "description": "system-process-integrity, ancestry-anomaly." },
  "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### ProcessTriageReport Schema
```json
{ "type": "object", "properties": {
  "FlaggedProcesses": { "type": "array", "items": { "$ref": "ProcessAnomaly" } }, "TotalProcesses": { "type": "integer" },
  "IntegrityFailures": { "type": "array", "items": { "$ref": "ProcessAnomaly" } },
  "AncestryAnomalies": { "type": "array", "items": { "$ref": "ProcessAnomaly" } } } }
```
### MalwareSuspect Schema
```json
{ "type": "object", "properties": {
  "Pid": { "type": "integer" }, "Process": { "type": "string" },
  "Categories": { "type": "array", "items": { "type": "string" }, "description": "rogue-process, process-anomaly, code-injection, network, yara-detection." },
  "Signals": { "type": "array", "items": { "type": "string" } }, "SignalCount": { "type": "integer" },
  "IsHighConfidence": { "type": "boolean", "description": "Corroborated by ≥2 categories." },
  "CommandLine": { "type": "string" }, "Sids": { "type": "array", "items": { "type": "string" } },
  "OrphanDlls": { "type": "array", "items": { "type": "string" } },
  "RemoteConnections": { "type": "array", "items": { "$ref": "WindowsNetScan" } },
  "DumpedFiles": { "type": "array", "items": { "type": "string" } },
  "YaraMatches": { "type": "array", "items": { "$ref": "YaraMatch" } } } }
```
### FindMalwareReport Schema
```json
{ "type": "object", "properties": {
  "RogueProcesses": { "$ref": "CrossViewHiddenProcessReport" }, "ProcessTriage": { "$ref": "ProcessTriageReport" },
  "NetworkArtifacts": { "$ref": "RemoteIpReport" }, "CodeInjection": { "$ref": "CodeInjectionReport" },
  "KernelRootkit": { "$ref": "KernelRootkitReport" },
  "Suspects": { "type": "array", "items": { "$ref": "MalwareSuspect" } },
  "HighConfidenceSuspects": { "type": "array", "items": { "$ref": "MalwareSuspect" } },
  "DumpedArtifacts": { "type": "array", "items": { "type": "string" } },
  "DumpYaraMatches": { "type": "array", "items": { "$ref": "YaraMatch" } },
  "YaraScan": { "$ref": "MemoryYaraReport", "description": "Present only when caller rules were supplied." } } }
```

---

## WindowsAnalysisWorkflow

### KeyRegistryArtifactsReport Schema
```json
{ "type": "object", "properties": {
  "Artifacts": { "type": "array", "items": { "$ref": "KeyRegistryArtifact" } },
  "AllEntries": { "type": "array", "items": { "$ref": "RegistryEntry" } } } }
```
### KeyRegistryArtifact Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string", "description": "Artifact category (Run keys, UserAssist, USBSTOR, …)." },
  "Entries": { "type": "array", "items": { "$ref": "RegistryEntry" } } } }
```
### ExternalShareConnectionsReport Schema
```json
{ "type": "object", "properties": { "RemoteShares": { "type": "array", "items": { "$ref": "ExternalShareConnection" } } } }
```
### ExternalShareConnection Schema
```json
{ "type": "object", "properties": {
  "Unc": { "type": "string" }, "Server": { "type": "string" }, "Share": { "type": "string" },
  "Source": { "type": "string", "description": "MountPoints2 / Map Network Drive MRU." },
  "LastWrite": { "type": "string", "format": "date-time" } } }
```
### ExecutionReport Schema
```json
{ "type": "object", "properties": {
  "Executables": { "type": "array", "items": { "$ref": "ExecutionArtifact" } },
  "SuspiciousExecutables": { "type": "array", "items": { "$ref": "ExecutionArtifact" } } } }
```
### ExecutionArtifact Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Sha1": { "type": "string" },
  "ShimcacheLastModified": { "type": "string", "format": "date-time" },
  "AmcacheTimestamp": { "type": "string", "format": "date-time" }, "CompileTime": { "type": "string", "format": "date-time" },
  "Sources": { "type": "array", "items": { "type": "string" }, "description": "Shimcache / Amcache." },
  "Suspicious": { "type": "boolean" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### WmiPersistenceReport Schema
```json
{ "type": "object", "properties": {
  "SuspiciousConsumers": { "type": "array", "items": { "$ref": "WmiPersistenceEntry" } },
  "Consumers": { "type": "array", "items": { "$ref": "WmiConsumer" } },
  "Bindings": { "type": "array", "items": { "$ref": "WmiBinding" } },
  "Filters": { "type": "array", "items": { "type": "string" } } } }
```
### WmiPersistenceEntry Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "string" }, "Name": { "type": "string" }, "Command": { "type": "string" },
  "DecodedCommand": { "type": "string", "description": "Decoded when the action was encoded PowerShell." },
  "FilterName": { "type": "string" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### DllHijackReport Schema
```json
{ "type": "object", "properties": {
  "Findings": { "type": "array", "items": { "$ref": "DllHijackFinding" } }, "DllsScanned": { "type": "integer" } } }
```
### DllHijackFinding Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Size": { "type": "integer" },
  "Kind": { "type": "string", "description": "Search-order shadow / Transient-location DLL." },
  "ShadowedSystemDll": { "type": "string" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### CredentialDumpReport Schema
```json
{ "type": "object", "properties": {
  "Findings": { "type": "array", "items": { "$ref": "CredentialDumpFinding" } }, "FilesScanned": { "type": "integer" } } }
```
### CredentialDumpFinding Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Size": { "type": "integer" },
  "Kind": { "type": "string", "description": "NTDS database / Registry hive dump / LSASS memory dump / Kerberos ticket." },
  "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### SuspiciousExecutableReport Schema
```json
{ "type": "object", "properties": {
  "Findings": { "type": "array", "items": { "$ref": "SuspiciousExecutable" } }, "FilesScanned": { "type": "integer" } } }
```
### SuspiciousExecutable Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Name": { "type": "string" }, "Size": { "type": "integer" },
  "Kind": { "type": "string", "description": "System-process masquerade / Transient-location executable." },
  "Impersonates": { "type": "string" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### LogonReport Schema
```json
{ "type": "object", "properties": {
  "Logons": { "type": "array", "items": { "$ref": "LogonEvent" } },
  "ByLogonType": { "type": "array", "items": { "$ref": "LogonTypeCount" } },
  "FailedLogons": { "type": "array", "items": { "$ref": "LogonEvent" } },
  "RemoteDesktopLogons": { "type": "array", "items": { "$ref": "LogonEvent" }, "description": "LogonType 10 (RDP)." },
  "NetworkLogons": { "type": "array", "items": { "$ref": "LogonEvent" }, "description": "LogonType 3." },
  "ExplicitCredentialLogons": { "type": "array", "items": { "$ref": "LogonEvent" }, "description": "4648 runas." },
  "NewCredentialLogons": { "type": "array", "items": { "$ref": "LogonEvent" }, "description": "LogonType 9." },
  "PrivilegedLogons": { "type": "array", "items": { "$ref": "LogonEvent" }, "description": "4672." } } }
```
### LogonEvent Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "EventId": { "type": "integer" }, "Success": { "type": "boolean" },
  "LogonType": { "type": "integer" }, "LogonTypeName": { "type": "string" },
  "TargetUser": { "type": "string" }, "TargetDomain": { "type": "string" }, "SubjectUser": { "type": "string" },
  "SourceIp": { "type": "string" }, "Workstation": { "type": "string" }, "AuthPackage": { "type": "string" },
  "LogonProcess": { "type": "string" }, "Computer": { "type": "string" } } }
```
### LogonTypeCount Schema
```json
{ "type": "object", "properties": { "LogonType": { "type": "integer" }, "Name": { "type": "string" }, "Count": { "type": "integer" } } }
```
### LateralMovementReport Schema
```json
{ "type": "object", "properties": {
  "RemoteLogons": { "type": "array", "items": { "$ref": "LogonEvent" } },
  "ExplicitCredentialLogons": { "type": "array", "items": { "$ref": "LogonEvent" } },
  "AdminShareAccess": { "type": "array", "items": { "$ref": "ShareAccess" } },
  "ServiceInstalls": { "type": "array", "items": { "$ref": "ServiceInstall" } },
  "SuspiciousServiceInstalls": { "type": "array", "items": { "$ref": "ServiceInstall" } } } }
```
### ShareAccess Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "ShareName": { "type": "string" }, "SharePath": { "type": "string" },
  "SourceIp": { "type": "string" }, "Account": { "type": "string" } } }
```
### ServiceInstall Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "EventId": { "type": "integer", "description": "4697 (Security) or 7045 (System)." },
  "ServiceName": { "type": "string" }, "ImagePath": { "type": "string" }, "ServiceType": { "type": "string" },
  "StartType": { "type": "string" }, "Account": { "type": "string" },
  "Suspicious": { "type": "boolean" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### KerberosReport Schema
```json
{ "type": "object", "properties": {
  "Events": { "type": "array", "items": { "$ref": "KerberosEvent" } },
  "PreAuthFailureBursts": { "type": "array", "items": { "$ref": "KerberosPreAuthBurst" } },
  "KerberoastingAttempts": { "type": "array", "items": { "$ref": "KerberosEvent" }, "description": "4769 RC4." },
  "AsRepRoastingAttempts": { "type": "array", "items": { "$ref": "KerberosEvent" }, "description": "4768 PreAuth=0." },
  "SuspiciousEvents": { "type": "array", "items": { "$ref": "KerberosEvent" } } } }
```
### KerberosEvent Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "EventId": { "type": "integer" },
  "TargetUser": { "type": "string" }, "TargetDomain": { "type": "string" }, "ServiceName": { "type": "string" },
  "ClientIp": { "type": "string" }, "TicketEncryptionType": { "type": "string", "description": "Hex, 0x17 = RC4-HMAC." },
  "TicketEncryptionName": { "type": "string" }, "Status": { "type": "string" }, "StatusName": { "type": "string" },
  "PreAuthType": { "type": "string" }, "Computer": { "type": "string" },
  "Suspicious": { "type": "boolean" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### KerberosPreAuthBurst Schema
```json
{ "type": "object", "properties": {
  "SourceIp": { "type": "string" }, "FailureCount": { "type": "integer" },
  "AffectedAccounts": { "type": "array", "items": { "type": "string" } },
  "FirstSeen": { "type": "string", "format": "date-time" }, "LastSeen": { "type": "string", "format": "date-time" } } }
```
### LogClearingReport Schema
```json
{ "type": "object", "properties": {
  "Events": { "type": "array", "items": { "$ref": "LogClearedEvent" } }, "Detected": { "type": "boolean" } } }
```
### LogClearedEvent Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "EventId": { "type": "integer", "description": "1102 (Security) / 104 (System)." },
  "ClearedLog": { "type": "string" }, "User": { "type": "string" }, "Computer": { "type": "string" } } }
```
### PowerShellReport Schema
```json
{ "type": "object", "properties": {
  "ScriptBlocks": { "type": "array", "items": { "$ref": "PowerShellScriptBlock" } },
  "SuspiciousScriptBlocks": { "type": "array", "items": { "$ref": "PowerShellScriptBlock" } } } }
```
### PowerShellScriptBlock Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "ScriptText": { "type": "string" }, "Path": { "type": "string" },
  "ScriptBlockId": { "type": "string" }, "DecodedText": { "type": "string" },
  "Suspicious": { "type": "boolean" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### RegistryPersistenceReport Schema
```json
{ "type": "object", "properties": {
  "Mechanisms": { "type": "array", "items": { "$ref": "RegistryPersistenceMechanism" } },
  "AllEntries": { "type": "array", "items": { "$ref": "PersistenceEntry" } },
  "SuspiciousEntries": { "type": "array", "items": { "$ref": "PersistenceEntry" } } } }
```
### RegistryPersistenceMechanism Schema
```json
{ "type": "object", "properties": {
  "Category": { "type": "string", "description": "Run Keys, Services, Scheduled Tasks, AppInit DLLs, Shell Commands." },
  "Entries": { "type": "array", "items": { "$ref": "PersistenceEntry" } } } }
```
### PersistenceEntry Schema
```json
{ "type": "object", "properties": {
  "Category": { "type": "string" }, "Hive": { "type": "string" }, "Plugin": { "type": "string" },
  "KeyPath": { "type": "string" }, "Name": { "type": "string" }, "Command": { "type": "string" },
  "LastWrite": { "type": "string" },
  "Suspicious": { "type": "boolean" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### ProcessNode Schema (input to ValidateProcessTreeAsync)
```json
{ "type": "object", "properties": {
  "Name": { "type": "string", "description": "Process image name, e.g. cmd.exe (required)." },
  "ParentName": { "type": "string", "description": "Parent image name — drives the tree checks." },
  "Path": { "type": "string", "description": "Full executable path — enables the path check when known." },
  "User": { "type": "string", "description": "User context — enables the SYSTEM/USER check when known." },
  "Pid": { "type": "integer" }, "Ppid": { "type": "integer" } } }
```
### ProcessExpectation Schema (entries of GetProcessExpectations)
```json
{ "type": "object", "properties": {
  "ProcessName": { "type": "string" },
  "ValidParents": { "type": "array", "items": { "type": "string" }, "description": "Whitelist; null/empty = any parent." },
  "SuspiciousParents": { "type": "array", "items": { "type": "string" }, "description": "Blacklist; null/empty = none." },
  "NeverSpawnsChildren": { "type": "boolean", "description": "Any child = process injection (critical)." },
  "ParentExits": { "type": "boolean" },
  "ValidPaths": { "type": "array", "items": { "type": "string" }, "description": "null/empty = any location." },
  "UserType": { "type": "string", "description": "SYSTEM, USER, or EITHER." },
  "ValidUsers": { "type": "array", "items": { "type": "string" } },
  "MinInstances": { "type": "integer" }, "MaxInstances": { "type": "integer" },
  "PerSession": { "type": "boolean" }, "RequiredArgs": { "type": "string" },
  "Source": { "type": "string" }, "Notes": { "type": "string" } } }
```
### ProcessExpectationFinding Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "string", "description": "injection_detected | suspicious_parent | unexpected_parent | unexpected_path | unexpected_user | too_few_instances | too_many_instances." },
  "Severity": { "type": "string", "description": "critical | high | medium." },
  "Description": { "type": "string" },
  "Expected": { "type": "array", "items": { "type": "string" } }, "Actual": { "type": "string" } } }
```
### ProcessExpectationCheck Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "ParentName": { "type": "string" }, "Pid": { "type": "integer" },
  "InExpectationsDb": { "type": "boolean", "description": "false = no expectation for this name; reported, not validated." },
  "Findings": { "type": "array", "items": { "$ref": "ProcessExpectationFinding" } },
  "Suspicious": { "type": "boolean" } } }
```
### ProcessTreeValidationReport Schema
```json
{ "type": "object", "properties": {
  "Processes": { "type": "array", "items": { "$ref": "ProcessExpectationCheck" } },
  "InstanceFindings": { "type": "array", "items": { "$ref": "ProcessExpectationFinding" }, "description": "Host-wide cardinality anomalies (only when checkInstanceCounts=true)." },
  "SuspiciousProcesses": { "type": "array", "items": { "$ref": "ProcessExpectationCheck" } } } }
```
### ShellItemReport Schema (AnalyzeShellItemsAsync)
```json
{ "type": "object", "properties": {
  "OpenedFiles": { "type": "array", "items": { "type": "object", "properties": {
    "Path": { "type": "string" }, "Source": { "type": "string", "description": "LNK | JumpList" }, "AppId": { "type": "string" },
    "TargetCreated": { "type": "string" }, "TargetModified": { "type": "string" }, "TargetAccessed": { "type": "string" },
    "FileSize": { "type": "integer" }, "Arguments": { "type": "string" }, "Drive": { "type": "string" },
    "VolumeSerialNumber": { "type": "string" }, "OpenedAround": { "type": "string" } } } },
  "FoldersAccessed": { "type": "array", "items": { "type": "object", "properties": {
    "Path": { "type": "string" }, "ShellType": { "type": "string" },
    "FirstInteracted": { "type": "string" }, "LastInteracted": { "type": "string" } } } },
  "ExternalDeviceEvidence": { "type": "array", "items": { "type": "object", "properties": {
    "Path": { "type": "string" }, "Indicator": { "type": "string", "description": "non-system drive X: | UNC/network share" },
    "Source": { "type": "string" }, "VolumeSerialNumber": { "type": "string" }, "When": { "type": "string" } } } } } }
```
### UsbDeviceReport Schema (AnalyzeUsbDevicesAsync)
```json
{ "type": "object", "properties": {
  "Devices": { "type": "array", "items": { "type": "object", "properties": {
    "SerialNumber": { "type": "string" }, "Vendor": { "type": "string" }, "Product": { "type": "string" }, "Revision": { "type": "string" },
    "FriendlyName": { "type": "string" }, "Vid": { "type": "string" }, "Pid": { "type": "string" },
    "VolumeName": { "type": "string" }, "DriveLetter": { "type": "string" }, "DeviceGuid": { "type": "string" },
    "ParentIdPrefix": { "type": "string" }, "User": { "type": "string" },
    "FirstConnected": { "type": "string" }, "LastConnected": { "type": "string" }, "LastRemoved": { "type": "string" },
    "InSetupApiLog": { "type": "boolean" }, "Sources": { "type": "array", "items": { "type": "string" } } } } } } }
```
### EmailArchiveReport Schema (AnalyzeEmailArchivesAsync)
```json
{ "type": "object", "properties": {
  "Archives": { "type": "array", "items": { "type": "object", "properties": {
    "Path": { "type": "string" },
    "Store": { "type": "object", "properties": { "ContentType": { "type": "string", "description": "PST | OST" }, "FileFormat": { "type": "string" }, "EncryptionType": { "type": "string" }, "FileSize": { "type": "integer" } } },
    "Messages": { "type": "array", "items": { "type": "object", "properties": {
      "Folder": { "type": "string" }, "From": { "type": "string" }, "To": { "type": "string" }, "Cc": { "type": "string" },
      "Subject": { "type": "string" }, "Date": { "type": "string" }, "SourceIp": { "type": "string" },
      "AttachmentNames": { "type": "array", "items": { "type": "string" } } } } },
    "MessageCount": { "type": "integer" }, "Folders": { "type": "array", "items": { "type": "string" } },
    "MessagesWithAttachments": { "type": "integer" }, "EarliestMessage": { "type": "string" }, "LatestMessage": { "type": "string" } } } } } }
```
### BrowserActivityReport Schema (AnalyzeBrowserActivityAsync)
```json
{ "type": "object", "properties": {
  "History": { "type": "array", "items": { "type": "object", "properties": {
    "Browser": { "type": "string", "description": "Chrome | Edge | Firefox | IE-Edge(WebCache)" },
    "Url": { "type": "string" }, "Title": { "type": "string" }, "VisitCount": { "type": "integer" },
    "LastVisited": { "type": "string", "description": "UTC" }, "Source": { "type": "string" } } } },
  "Downloads": { "type": "array", "items": { "type": "object", "properties": {
    "Browser": { "type": "string" }, "Url": { "type": "string" }, "TargetPath": { "type": "string" },
    "TotalBytes": { "type": "integer" }, "StartTime": { "type": "string" }, "Source": { "type": "string" } } } },
  "Sources": { "type": "array", "items": { "type": "string" } } } }
```

---

## TimelineAnalysisWorkflow

### SuperTimeline Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Events": { "type": "array", "items": { "$ref": "TimelineEvent" } },
  "TotalEventsInStorage": { "type": "integer" },
  "ParserCounts": { "type": "object", "description": "Per-parser event counts (from pinfo)." },
  "Filter": { "type": "string" }, "EventCount": { "type": "integer" },
  "Start": { "type": "string", "format": "date-time" }, "End": { "type": "string", "format": "date-time" },
  "TopParsers": { "type": "array", "description": "Parser→count pairs, descending." } } }
```
### CategorizedTimeline Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Categories": { "type": "array", "items": { "$ref": "TimelineCategory" } },
  "TotalTaggedEvents": { "type": "integer" }, "PopulatedCategories": { "type": "array", "items": { "type": "string" } } } }
```
### TimelineCategory Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string", "description": "'Evidence of…' category." },
  "Events": { "type": "array", "items": { "$ref": "TimelineEvent" } }, "Count": { "type": "integer" } } }
```
### TimelinePivotReport Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Pivots": { "type": "array", "items": { "$ref": "TimelinePivot" } },
  "AlertsConsidered": { "type": "integer" }, "SliceSizeMinutes": { "type": "integer" } } }
```
### TimelinePivot Schema
```json
{ "type": "object", "properties": {
  "Alert": { "$ref": "HayabusaAlert" }, "PivotTime": { "type": "string", "format": "date-time" },
  "Surrounding": { "type": "array", "items": { "$ref": "TimelineEvent" } }, "SurroundingCount": { "type": "integer" } } }
```
### TimelineTriageReport Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Pivots": { "type": "array", "items": { "$ref": "TimelineTriagePivot" } },
  "TotalEvents": { "type": "integer" }, "Candidates": { "type": "integer" }, "CompressionRatio": { "type": "number" } } }
```
### TimelineTriagePivot Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "EventType": { "type": "string" },
  "Bits": { "type": "number", "description": "Total surprisal." }, "EventCount": { "type": "integer" },
  "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### AutoPivotReport Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Pivots": { "type": "array", "items": { "$ref": "ExpandedPivot" } },
  "TotalEvents": { "type": "integer" }, "Candidates": { "type": "integer" }, "SliceSizeMinutes": { "type": "integer" } } }
```
### ExpandedPivot Schema
```json
{ "type": "object", "properties": {
  "Pivot": { "$ref": "TimelineTriagePivot" },
  "Surrounding": { "type": "array", "items": { "$ref": "TimelineEvent" } }, "SurroundingCount": { "type": "integer" } } }
```
### TimelineSearchReport Schema
```json
{ "type": "object", "properties": {
  "StorageFile": { "type": "string" }, "Hits": { "type": "array", "items": { "$ref": "TimelineKeywordHits" } },
  "Matches": { "type": "array", "items": { "$ref": "TimelineEvent" }, "description": "De-duplicated union, time-ordered." },
  "MatchedKeywords": { "type": "array", "items": { "type": "string" } } } }
```
### TimelineKeywordHits Schema
```json
{ "type": "object", "properties": {
  "Keyword": { "type": "string" }, "Events": { "type": "array", "items": { "$ref": "TimelineEvent" } }, "Count": { "type": "integer" } } }
```

---

## AntiForensicsAnalysisWorkflow

### TimestompReport Schema
```json
{ "type": "object", "properties": {
  "MftFile": { "type": "string" }, "Findings": { "type": "array", "items": { "$ref": "TimestompFinding" } },
  "EntriesScanned": { "type": "integer" } } }
```
### TimestompFinding Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "SiCreated": { "type": "string", "format": "date-time" },
  "SiBeforeFn": { "type": "boolean" }, "ZeroSubseconds": { "type": "boolean" },
  "NeighborCreated": { "type": "string", "format": "date-time", "description": "Median creation of MFT-adjacent in-use files." },
  "DeviationHours": { "type": "number", "description": "|SiCreated − NeighborCreated| in hours; high = backdated." } } }
```
### UsnAnomalyReport Schema
```json
{ "type": "object", "properties": {
  "UsnFile": { "type": "string" }, "Pivots": { "type": "array", "items": { "$ref": "TimelineTriagePivot" } },
  "RecordsScanned": { "type": "integer" }, "Candidates": { "type": "integer" }, "CompressionRatio": { "type": "number" } } }
```

---

## WebServerAnalysisWorkflow

### WebServerLogReport Schema
```json
{ "type": "object", "properties": {
  "LogPath": { "type": "string" }, "SuspiciousLineCount": { "type": "integer" }, "Truncated": { "type": "boolean" },
  "Findings": { "type": "array", "items": { "$ref": "WebLogFinding" } },
  "TopAttackerIps": { "type": "array", "items": { "$ref": "IpHitCount" } },
  "ScannerUserAgents": { "type": "array", "items": { "type": "string" } },
  "CategoryBreakdown": { "type": "array", "items": { "$ref": "CategoryCount" } },
  "DecodedPayloads": { "type": "array", "items": { "$ref": "DecodedPayload" } } } }
```
### WebLogFinding Schema
```json
{ "type": "object", "properties": {
  "ClientIp": { "type": "string" }, "Timestamp": { "type": "string" }, "Method": { "type": "string" },
  "Url": { "type": "string" }, "Status": { "type": "integer" }, "UserAgent": { "type": "string" },
  "Categories": { "type": "array", "items": { "type": "string" }, "description": "scanner, sqli, webshell-rce, file-inclusion, xss." },
  "Reasons": { "type": "array", "items": { "type": "string" } },
  "DecodedPayload": { "type": "string", "description": "Decoded injected script, when one was carried." } } }
```
### IpHitCount Schema
```json
{ "type": "object", "properties": { "Ip": { "type": "string" }, "Hits": { "type": "integer" } } }
```
### CategoryCount Schema
```json
{ "type": "object", "properties": { "Category": { "type": "string" }, "Count": { "type": "integer" } } }
```
### DecodedPayload Schema
```json
{ "type": "object", "properties": {
  "ClientIp": { "type": "string" }, "Hex": { "type": "string", "description": "Truncated source hex." }, "Decoded": { "type": "string" } } }
```
### WebshellScanReport Schema
```json
{ "type": "object", "properties": {
  "WebRoot": { "type": "string" }, "RulesFile": { "type": "string" },
  "Matches": { "type": "array", "items": { "$ref": "YaraMatch" } },
  "Files": { "type": "array", "items": { "$ref": "WebshellFile" } }, "FilesFlagged": { "type": "integer" } } }
```
### WebshellFile Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Rules": { "type": "array", "items": { "type": "string" }, "description": "Distinct rules that fired (a real shell trips many)." } } }
```

---

## MemoryAnalysisToolkit (Linux plugins)

Address/offset fields are rendered by Volatility as `"0x…"` strings. Each row also carries `__children` (array).

### LinuxPsList Schema
```json
{ "type": "object", "properties": {
  "Offset": { "type": "string" }, "PID": { "type": "integer" }, "TID": { "type": "integer" }, "PPID": { "type": "integer" },
  "COMM": { "type": "string" }, "UID": { "type": "integer" }, "GID": { "type": "integer" },
  "EUID": { "type": "integer" }, "EGID": { "type": "integer" },
  "CreationTime": { "type": "string", "format": "date-time" }, "FileOutput": { "type": "string" } } }
```
### LinuxPsScan Schema
```json
{ "type": "object", "properties": {
  "Offset": { "type": "string" }, "PID": { "type": "integer" }, "TID": { "type": "integer" }, "PPID": { "type": "integer" },
  "COMM": { "type": "string" }, "EXIT_STATE": { "type": "string" } } }
```
### LinuxPsTree Schema
```json
{ "type": "object", "properties": {
  "Offset": { "type": "string" }, "PID": { "type": "integer" }, "TID": { "type": "integer" }, "PPID": { "type": "integer" },
  "COMM": { "type": "string" }, "__children": { "type": "array", "items": { "$ref": "LinuxPsTree" } } } }
```
### LinuxPsAux Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "PPID": { "type": "integer" }, "COMM": { "type": "string" }, "ARGS": { "type": "string" } } }
```
### LinuxBash Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" },
  "CommandTime": { "type": "string", "format": "date-time" }, "Command": { "type": "string" } } }
```
### LinuxLsof Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "TID": { "type": "integer" }, "Process": { "type": "string" }, "FD": { "type": "integer" },
  "Path": { "type": "string" }, "Device": { "type": "string" }, "Inode": { "type": "integer" },
  "Type": { "type": "string" }, "Mode": { "type": "string" }, "Size": { "type": "integer" },
  "Changed": { "type": "string", "format": "date-time" }, "Modified": { "type": "string", "format": "date-time" },
  "Accessed": { "type": "string", "format": "date-time" } } }
```
### LinuxSockstat Schema
```json
{ "type": "object", "properties": {
  "NetNS": { "type": "integer" }, "ProcessName": { "type": "string" }, "PID": { "type": "integer" }, "TID": { "type": "integer" },
  "FD": { "type": "integer" }, "SockOffset": { "type": "string" }, "Family": { "type": "string" }, "Type": { "type": "string" },
  "Proto": { "type": "string" }, "SourceAddr": { "type": "string" }, "SourcePort": { "type": "string" },
  "DestinationAddr": { "type": "string" }, "DestinationPort": { "type": "string" }, "State": { "type": "string" }, "Filter": { "type": "string" } } }
```
### LinuxModule Schema
```json
{ "type": "object", "description": "Shared by LinuxLsmodAsync / LinuxCheckModulesAsync / LinuxHiddenModulesAsync.", "properties": {
  "Offset": { "type": "string" }, "ModuleName": { "type": "string" }, "CodeSize": { "type": "string" },
  "Taints": { "type": "string" }, "LoadArguments": { "type": "string" }, "FileOutput": { "type": "string" } } }
```
### LinuxMalfind Schema
```json
{ "type": "object", "properties": {
  "PID": { "type": "integer" }, "Process": { "type": "string" }, "Start": { "type": "string" }, "End": { "type": "string" },
  "Path": { "type": "string" }, "Protection": { "type": "string" }, "Hexdump": { "type": "string" }, "Disasm": { "type": "string" } } }
```
### LinuxTtyCheck Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Address": { "type": "string" }, "Module": { "type": "string" }, "Symbol": { "type": "string" } } }
```
### LinuxCheckSyscall Schema
```json
{ "type": "object", "properties": {
  "TableAddress": { "type": "string" }, "TableName": { "type": "string" }, "Index": { "type": "integer" },
  "HandlerAddress": { "type": "string" }, "HandlerSymbol": { "type": "string" } } }
```
### LinuxCheckAfinfo Schema
```json
{ "type": "object", "properties": {
  "SymbolName": { "type": "string" }, "Member": { "type": "string" }, "HandlerAddress": { "type": "string" } } }
```
### LinuxNetfilter Schema
```json
{ "type": "object", "properties": {
  "NetNS": { "type": "integer" }, "Proto": { "type": "string" }, "Hook": { "type": "string" }, "Priority": { "type": "integer" },
  "Handler": { "type": "string" }, "Module": { "type": "string" }, "Symbol": { "type": "string" }, "IsHooked": { "type": "string" } } }
```
### LinuxCheckCreds Schema
```json
{ "type": "object", "properties": { "CredVAddr": { "type": "string" }, "PIDs": { "type": "string" } } }
```
### LinuxKmsg Schema
```json
{ "type": "object", "properties": {
  "Facility": { "type": "string" }, "Level": { "type": "string" }, "Timestamp": { "type": "string" },
  "Caller": { "type": "string" }, "Line": { "type": "string" } } }
```

---

## LinuxAnalysisToolkit

### LinuxSystemInfo Schema
```json
{ "type": "object", "properties": {
  "Hostname": { "type": "string" }, "PrettyName": { "type": "string" }, "DistroId": { "type": "string" },
  "VersionId": { "type": "string" }, "Name": { "type": "string" }, "Version": { "type": "string" },
  "Timezone": { "type": "string" }, "MachineId": { "type": "string" }, "IdLike": { "type": "string" } } }
```
### LinuxUserAccount Schema
```json
{ "type": "object", "properties": {
  "Username": { "type": "string" }, "Uid": { "type": "integer" }, "Gid": { "type": "integer" },
  "Gecos": { "type": "string" }, "Home": { "type": "string" }, "Shell": { "type": "string" },
  "HasLoginShell": { "type": "boolean" }, "IsSystemAccount": { "type": "boolean" },
  "PasswordState": { "type": "string", "enum": ["set", "empty", "locked", "none", "unknown"] },
  "PasswordLastChanged": { "type": "string", "format": "date-time" } } }
```
### SudoRule Schema
```json
{ "type": "object", "properties": {
  "Source": { "type": "string" }, "Raw": { "type": "string" }, "Principal": { "type": "string" }, "Spec": { "type": "string" },
  "NoPasswd": { "type": "boolean" }, "GrantsAll": { "type": "boolean" } } }
```
### CronEntry Schema
```json
{ "type": "object", "properties": {
  "Source": { "type": "string" }, "User": { "type": "string" }, "Schedule": { "type": "string" },
  "Command": { "type": "string" }, "Raw": { "type": "string" }, "IsReboot": { "type": "boolean" } } }
```
### LinuxLogin Schema
```json
{ "type": "object", "properties": {
  "User": { "type": "string" }, "Terminal": { "type": "string" }, "Host": { "type": "string" },
  "Start": { "type": "string", "format": "date-time" }, "Status": { "type": "string" },
  "StillLoggedIn": { "type": "boolean" }, "Raw": { "type": "string" } } }
```
### UtmpRecord Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "integer" }, "TypeName": { "type": "string" }, "Pid": { "type": "integer" }, "Id": { "type": "string" },
  "User": { "type": "string" }, "Line": { "type": "string" }, "Host": { "type": "string" }, "Address": { "type": "string" },
  "Time": { "type": "string", "format": "date-time" } } }
```
### JournalEntry Schema
```json
{ "type": "object", "properties": {
  "Timestamp": { "type": "string", "format": "date-time" }, "Unit": { "type": "string" }, "Identifier": { "type": "string" },
  "Pid": { "type": "integer" }, "Uid": { "type": "integer" }, "Priority": { "type": "integer" },
  "Hostname": { "type": "string" }, "Message": { "type": "string" } } }
```
### LinuxPackage Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Version": { "type": "string" }, "Architecture": { "type": "string" },
  "Status": { "type": "string" }, "Section": { "type": "string" }, "Priority": { "type": "string" }, "Installed": { "type": "boolean" } } }
```
### PackageEvent Schema
```json
{ "type": "object", "properties": {
  "Timestamp": { "type": "string", "format": "date-time" }, "Action": { "type": "string" }, "Package": { "type": "string" },
  "Version": { "type": "string" }, "PreviousVersion": { "type": "string" }, "Source": { "type": "string" } } }
```
### ShellHistoryEntry Schema
```json
{ "type": "object", "properties": {
  "User": { "type": "string" }, "HistoryFile": { "type": "string" }, "LineNumber": { "type": "integer" },
  "Command": { "type": "string" }, "Timestamp": { "type": "string", "format": "date-time" } } }
```
### ClamAvMatch Schema
```json
{ "type": "object", "properties": { "Path": { "type": "string" }, "Signature": { "type": "string" } } }
```
### LinuxFile Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Mode": { "type": "string", "description": "Octal, e.g. 4755." },
  "Owner": { "type": "string" }, "Group": { "type": "string" }, "Size": { "type": "integer" },
  "Modified": { "type": "string", "format": "date-time" },
  "IsSetuid": { "type": "boolean" }, "IsSetgid": { "type": "boolean" }, "IsExecutable": { "type": "boolean" } } }
```

---

## LinuxAnalysisWorkflow

### UserAccountReport Schema
```json
{ "type": "object", "properties": {
  "Accounts": { "type": "array", "items": { "$ref": "LinuxUserAccount" } },
  "SudoRules": { "type": "array", "items": { "$ref": "SudoRule" } },
  "Findings": { "type": "array", "items": { "$ref": "AccountFinding" } }, "TotalAccounts": { "type": "integer" } } }
```
### AccountFinding Schema
```json
{ "type": "object", "properties": {
  "Username": { "type": "string" }, "Issue": { "type": "string", "description": "uid0-extra | empty-password | service-account-login-shell | sudo-nopasswd | sudo-all" }, "Detail": { "type": "string" } } }
```
### LoginActivityReport Schema
```json
{ "type": "object", "properties": {
  "SuccessfulCount": { "type": "integer" }, "FailedCount": { "type": "integer" },
  "TopSourceIps": { "type": "array", "items": { "$ref": "IpLoginStat" } },
  "TopFailedUsers": { "type": "array", "items": { "$ref": "NameCount" } },
  "RecentSuccessful": { "type": "array", "items": { "$ref": "LinuxLogin" } },
  "Findings": { "type": "array", "items": { "$ref": "LoginFinding" } } } }
```
### IpLoginStat Schema
```json
{ "type": "object", "properties": { "Ip": { "type": "string" }, "Successful": { "type": "integer" }, "Failed": { "type": "integer" } } }
```
### NameCount Schema
```json
{ "type": "object", "properties": { "Name": { "type": "string" }, "Count": { "type": "integer" } } }
```
### LoginFinding Schema
```json
{ "type": "object", "properties": { "Category": { "type": "string" }, "Detail": { "type": "string" } } }
```
### AuthEventReport Schema
```json
{ "type": "object", "properties": {
  "LogPath": { "type": "string" }, "AcceptedLogins": { "type": "integer" }, "FailedLogins": { "type": "integer" },
  "SudoCommands": { "type": "integer" }, "TopSshSourceIps": { "type": "array", "items": { "$ref": "IpLoginStat" } },
  "Events": { "type": "array", "items": { "$ref": "AuthEvent" } }, "Findings": { "type": "array", "items": { "$ref": "AuthEvent" } } } }
```
### AuthEvent Schema
```json
{ "type": "object", "properties": {
  "Time": { "type": "string", "format": "date-time" }, "Type": { "type": "string" }, "User": { "type": "string" },
  "SourceIp": { "type": "string" }, "Raw": { "type": "string" } } }
```
### LinuxPersistenceReport Schema
```json
{ "type": "object", "properties": {
  "Items": { "type": "array", "items": { "$ref": "PersistenceItem" } },
  "Suspicious": { "type": "array", "items": { "$ref": "PersistenceItem" } }, "TotalItems": { "type": "integer" } } }
```
### PersistenceItem Schema
```json
{ "type": "object", "properties": {
  "Mechanism": { "type": "string" }, "Source": { "type": "string" }, "Detail": { "type": "string" },
  "Score": { "type": "integer" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### ShellHistoryReport Schema
```json
{ "type": "object", "properties": {
  "TotalLines": { "type": "integer" }, "UsersWithHistory": { "type": "integer" },
  "Suspicious": { "type": "array", "items": { "$ref": "SuspiciousCommand" } } } }
```
### SuspiciousCommand Schema
```json
{ "type": "object", "properties": {
  "User": { "type": "string" }, "Command": { "type": "string" }, "Categories": { "type": "array", "items": { "type": "string" } },
  "Timestamp": { "type": "string", "format": "date-time" }, "HistoryFile": { "type": "string" } } }
```
### PackageReport Schema
```json
{ "type": "object", "properties": {
  "InstalledCount": { "type": "integer" }, "RecentEvents": { "type": "array", "items": { "$ref": "PackageEvent" } },
  "Findings": { "type": "array", "items": { "$ref": "PackageEvent" } } } }
```
### FileAnomalyReport Schema
```json
{ "type": "object", "properties": {
  "SuspiciousSetuid": { "type": "array", "items": { "$ref": "LinuxFile" } }, "TotalSetuid": { "type": "integer" },
  "WorldWritable": { "type": "array", "items": { "$ref": "LinuxFile" } },
  "ExecutablesInTempDirs": { "type": "array", "items": { "$ref": "LinuxFile" } } } }
```
### LinuxMalwareReport Schema
```json
{ "type": "object", "properties": {
  "Target": { "type": "string" }, "ClamMatches": { "type": "array", "items": { "$ref": "ClamAvMatch" } },
  "YaraMatches": { "type": "array", "items": { "$ref": "YaraMatch" } }, "Note": { "type": "string" } } }
```
### JournalReport Schema
```json
{ "type": "object", "properties": {
  "JournalDir": { "type": "string" }, "TotalEntries": { "type": "integer" }, "SudoEvents": { "type": "integer" },
  "SshEvents": { "type": "integer" }, "ServiceStarts": { "type": "integer" },
  "Notable": { "type": "array", "items": { "$ref": "JournalEntry" } } } }
```
### LinuxHostTriageReport Schema
```json
{ "type": "object", "properties": {
  "System": { "$ref": "LinuxSystemInfo" }, "Accounts": { "$ref": "UserAccountReport" }, "Logins": { "$ref": "LoginActivityReport" },
  "Auth": { "$ref": "AuthEventReport" }, "Persistence": { "$ref": "LinuxPersistenceReport" },
  "ShellHistory": { "$ref": "ShellHistoryReport" }, "Files": { "$ref": "FileAnomalyReport" },
  "TopFindings": { "type": "array", "items": { "type": "string" } } } }
```

---

## PacketAnalysisToolkit

### PcapInfo Schema
```json
{ "type": "object", "properties": {
  "FileName": { "type": "string" }, "FileType": { "type": "string" }, "Encapsulation": { "type": "string" },
  "PacketCount": { "type": "integer" }, "FileSize": { "type": "integer" }, "DataSize": { "type": "integer" },
  "DurationSeconds": { "type": "number" }, "FirstPacketTime": { "type": "string", "format": "date-time" },
  "LastPacketTime": { "type": "string", "format": "date-time" }, "DataByteRate": { "type": "number" },
  "AveragePacketSize": { "type": "number" }, "Sha256": { "type": "string" }, "Sha1": { "type": "string" } } }
```
### PacketSummary Schema
```json
{ "type": "object", "properties": {
  "Number": { "type": "integer" }, "Time": { "type": "number", "description": "Epoch seconds." },
  "Source": { "type": "string" }, "Destination": { "type": "string" }, "Protocol": { "type": "string" },
  "Length": { "type": "integer" }, "Info": { "type": "string" } } }
```
### ProtocolLayer Schema
```json
{ "type": "object", "properties": {
  "Protocol": { "type": "string" }, "Depth": { "type": "integer", "description": "Nesting level (0 = link)." },
  "Frames": { "type": "integer" }, "Bytes": { "type": "integer" } } }
```
### Conversation Schema
```json
{ "type": "object", "properties": {
  "EndpointA": { "type": "string" }, "EndpointB": { "type": "string" },
  "FramesAToB": { "type": "integer" }, "BytesAToB": { "type": "integer" },
  "FramesBToA": { "type": "integer" }, "BytesBToA": { "type": "integer" },
  "TotalFrames": { "type": "integer" }, "TotalBytes": { "type": "integer" },
  "RelativeStart": { "type": "number" }, "Duration": { "type": "number" } } }
```
### Endpoint Schema
```json
{ "type": "object", "properties": {
  "Address": { "type": "string" }, "Packets": { "type": "integer" }, "Bytes": { "type": "integer" },
  "TxPackets": { "type": "integer" }, "TxBytes": { "type": "integer" },
  "RxPackets": { "type": "integer" }, "RxBytes": { "type": "integer" } } }
```
### TcpTraceConn Schema
```json
{ "type": "object", "properties": {
  "HostA": { "type": "string" }, "PortA": { "type": "integer" }, "HostB": { "type": "string" }, "PortB": { "type": "integer" },
  "Label": { "type": "string" }, "PacketsAToB": { "type": "integer" }, "PacketsBToA": { "type": "integer" }, "Complete": { "type": "boolean" } } }
```
### NgrepMatch Schema
```json
{ "type": "object", "properties": {
  "Protocol": { "type": "string", "description": "T (TCP) or U (UDP)." }, "Source": { "type": "string" },
  "Destination": { "type": "string" }, "Flags": { "type": "string" }, "Payload": { "type": "string" } } }
```
### P0fRecord Schema
```json
{ "type": "object", "properties": {
  "Subject": { "type": "string", "description": "client | server." }, "Address": { "type": "string" },
  "Os": { "type": "string" }, "Detail": { "type": "string" } } }
```
### NetflowRecord Schema
```json
{ "type": "object", "properties": {
  "Start": { "type": "string", "format": "date-time" }, "Duration": { "type": "number" }, "Proto": { "type": "string" },
  "SrcIp": { "type": "string" }, "SrcPort": { "type": "integer" }, "DstIp": { "type": "string" }, "DstPort": { "type": "integer" },
  "Packets": { "type": "integer" }, "Bytes": { "type": "integer" }, "Flags": { "type": "string" } } }
```
### SuricataAlert Schema
```json
{ "type": "object", "properties": {
  "Timestamp": { "type": "string", "format": "date-time" }, "SrcIp": { "type": "string" }, "SrcPort": { "type": "integer" },
  "DestIp": { "type": "string" }, "DestPort": { "type": "integer" }, "Proto": { "type": "string" }, "AppProto": { "type": "string" },
  "SignatureId": { "type": "integer" }, "Signature": { "type": "string" }, "Category": { "type": "string" },
  "Severity": { "type": "integer", "description": "1 = most severe … 3 = informational." },
  "HttpHost": { "type": "string" }, "HttpUrl": { "type": "string" } } }
```

---

## PacketAnalysisWorkflow

### PcapTriageReport Schema
```json
{ "type": "object", "properties": {
  "Info": { "$ref": "PcapInfo" }, "ProtocolHierarchy": { "type": "array", "items": { "$ref": "ProtocolLayer" } },
  "TopConversations": { "type": "array", "items": { "$ref": "Conversation" } },
  "TopEndpoints": { "type": "array", "items": { "$ref": "Endpoint" } },
  "TopDnsQueries": { "type": "array", "items": { "$ref": "NameCount" } },
  "TopHttpHosts": { "type": "array", "items": { "$ref": "NameCount" } } } }
```
### StreamReport Schema
```json
{ "type": "object", "properties": {
  "Protocol": { "type": "string" }, "Index": { "type": "integer" }, "Content": { "type": "string" },
  "Highlights": { "type": "array", "items": { "type": "string" } } } }
```
### DnsTunnelingReport Schema
```json
{ "type": "object", "properties": {
  "TotalQueries": { "type": "integer" }, "UniqueDomains": { "type": "integer" },
  "SuspiciousDomains": { "type": "array", "items": { "$ref": "DnsDomainFinding" } } } }
```
### DnsDomainFinding Schema
```json
{ "type": "object", "properties": {
  "Domain": { "type": "string" }, "QueryCount": { "type": "integer" }, "UniqueSubdomains": { "type": "integer" },
  "MaxLabelLength": { "type": "integer" }, "AvgEntropy": { "type": "number" },
  "RareTypes": { "type": "array", "items": { "type": "string" } },
  "Score": { "type": "integer" }, "Reasons": { "type": "array", "items": { "type": "string" } } } }
```
### HttpObjectReport Schema
```json
{ "type": "object", "properties": {
  "OutDir": { "type": "string" }, "CarvedFiles": { "type": "array", "items": { "type": "string" } },
  "Transactions": { "type": "array", "items": { "$ref": "HttpTransaction" } } } }
```
### HttpTransaction Schema
```json
{ "type": "object", "properties": {
  "Method": { "type": "string" }, "Host": { "type": "string" }, "Uri": { "type": "string" }, "UserAgent": { "type": "string" } } }
```
### PcapCredentialReport Schema
```json
{ "type": "object", "properties": { "Findings": { "type": "array", "items": { "$ref": "CredentialFinding" } } } }
```
### CredentialFinding Schema
```json
{ "type": "object", "properties": {
  "Protocol": { "type": "string", "description": "http-basic | ftp | http-form | telnet | smtp-auth | pop | imap" },
  "Source": { "type": "string" }, "Destination": { "type": "string" },
  "Username": { "type": "string" }, "Password": { "type": "string" }, "Detail": { "type": "string" } } }
```
### BeaconReport Schema
```json
{ "type": "object", "properties": { "Beacons": { "type": "array", "items": { "$ref": "BeaconFinding" } } } }
```
### BeaconFinding Schema
```json
{ "type": "object", "properties": {
  "Source": { "type": "string" }, "Destination": { "type": "string" }, "DestinationPort": { "type": "integer" },
  "ConnectionCount": { "type": "integer" }, "MeanIntervalSeconds": { "type": "number" },
  "JitterRatio": { "type": "number", "description": "stddev/mean of intervals; near 0 = metronomic beacon." }, "Score": { "type": "integer" } } }
```
### HostFingerprintReport Schema
```json
{ "type": "object", "properties": { "Hosts": { "type": "array", "items": { "$ref": "HostFingerprint" } } } }
```
### HostFingerprint Schema
```json
{ "type": "object", "properties": {
  "Address": { "type": "string" }, "Role": { "type": "string" }, "OsGuesses": { "type": "array", "items": { "type": "string" } } } }
```
### IdsReport Schema
```json
{ "type": "object", "properties": {
  "AlertCount": { "type": "integer" }, "BySignature": { "type": "array", "items": { "$ref": "NameCount" } },
  "BySeverity": { "type": "array", "items": { "$ref": "NameCount" } },
  "TopSourceIps": { "type": "array", "items": { "$ref": "NameCount" } },
  "Alerts": { "type": "array", "items": { "$ref": "SuricataAlert" } } } }
```

---

## DiskAnalysisToolkit / DiskAnalysisWorkflow (carving & recovery)

### CarvedFile Schema
```json
{ "type": "object", "properties": {
  "Type": { "type": "string", "description": "jpg/png/pdf/zip/…" }, "Name": { "type": "string" },
  "Size": { "type": "integer" }, "Path": { "type": "string" },
  "Offset": { "type": "integer", "description": "Byte offset within the carved input." }, "Comment": { "type": "string" } } }
```
### BulkFeatureFile Schema
```json
{ "type": "object", "properties": {
  "Name": { "type": "string" }, "Category": { "type": "string", "description": "email/url/domain/ccn/telephone/ip/…" },
  "Count": { "type": "integer" }, "Path": { "type": "string" },
  "TopValues": { "type": "array", "items": { "type": "string" } } } }
```
### CarveReport Schema
```json
{ "type": "object", "properties": {
  "OutputDir": { "type": "string" }, "Carver": { "type": "string" },
  "CarvedFiles": { "type": "array", "items": { "$ref": "CarvedFile" } },
  "ByType": { "type": "array", "items": { "$ref": "NameCount" } }, "TotalFiles": { "type": "integer" } } }
```
### FeatureExtractionReport Schema
```json
{ "type": "object", "properties": {
  "OutputDir": { "type": "string" }, "Features": { "type": "array", "items": { "$ref": "FeatureCategory" } } } }
```
### FeatureCategory Schema
```json
{ "type": "object", "properties": {
  "Category": { "type": "string" }, "Count": { "type": "integer" },
  "TopValues": { "type": "array", "items": { "type": "string" } } } }
```
### DeletedFilesReport Schema
```json
{ "type": "object", "properties": {
  "DeletedFiles": { "type": "array", "items": { "$ref": "DeletedFileEntry" } }, "Count": { "type": "integer" } } }
```
### DeletedFileEntry Schema
```json
{ "type": "object", "properties": {
  "Path": { "type": "string" }, "Inode": { "type": "string", "description": "TSK inode address (pass to RecoverDeletedFileAsync)." },
  "Size": { "type": "integer" }, "DeletedTime": { "type": "string", "format": "date-time" },
  "Recoverable": { "type": "boolean", "description": "False when the inode was reallocated (content likely overwritten)." } } }
```
