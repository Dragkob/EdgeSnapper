<p align="center">
  <img width="496" height="279" alt="edgesnap" src="https://github.com/user-attachments/assets/fa88553a-78f0-4c74-b91c-ae1536ae9c58" />
</p>
<br />

**EdgeSnapper** is a security research toolkit focused on analyzing cleartext credential persistence within Microsoft Edge process memory. The project demonstrates how credentials protected by front-end UI mechanisms (Windows Hello, biometrics, password reveal restrictions, etc.) may still transiently exist in readable process memory during runtime.

The toolkit provides both: Live in-memory inspection & Offline forensic dump analysis for defensive research, memory forensics, and browser security auditing.


## Attack Paths

| Path | Method | Workflow | Result |
|---|---|---|---|
| **Path Alpha** | **Live In-Memory Extraction** | `EdgeSnapper.cpp` locates the target `msedge.exe` process, acquires a read handle, creates a PSS snapshot context, scans committed RW memory regions with regex-based parsing, and prints matching credential patterns directly to the console | ✅ No dump file written to disk |
| **Path Beta** | **Disk Dump + Offline Parsing** | `EdgeSnapperOnDisk.cpp` snapshots the Edge process and writes a full-memory `.dmp` using `MiniDumpWriteDump`. The resulting dump is then processed by the PowerShell parser `credHarvester.ps1` for offline extraction and filtering | ✅ Persistent forensic artifact for post-analysis |


## Suite Components

| Component | Language | Operation Type | Description |
|---|---|---|---|
| **EdgeSnapper** | C++ | Live RAM Scanner | Enumerates the target process, captures a snapshot context using `PssCaptureSnapshot`, scans readable memory regions with `VirtualQueryEx`, and parses credential-like structures directly from live memory |
| **EdgeSnapperOnDisk** | C++ | Memory Dumper | Creates a full-process memory dump using `MiniDumpWriteDump(MiniDumpWithFullMemory)` after establishing a stable snapshot context |
| **HarvestPro** | PowerShell | Offline Dump Parser | Loads the `.dmp` into memory using .NET file handling, applies regex extraction logic, removes telemetry noise, and deduplicates recovered credential artifacts |


## Snapshotting Strategy

Both native utilities utilize ```PssCaptureSnapshot()``` to stabilize process state before memory inspection or dumping.

This helps reduce:
- Torn reads
- Race conditions
- Inconsistent memory regions
- Active allocation corruption during scanning

#<img width="1920" height="1080" alt="edgesnap" src="https://github.com/user-attachments/assets/da789303-b3ed-48b4-879d-d6c8329feac0" />


> [!WARNING]
> This project is intended strictly for:
> - Authorized security auditing
> - Memory forensics research
> - Defensive browser security analysis
> - Educational purposes
>
> The toolkit is designed to demonstrate the security implications of transient cleartext credential exposure in application memory.
>
> Unauthorized use against systems, accounts, or environments without explicit permission is prohibited.
