<p align="center">
  <img width="2512" height="416" alt="wowbanner" src="https://github.com/user-attachments/assets/0390e336-431e-45ed-96c3-a0339ab1fe67" />
</p>
<br />

**EdgeSnapper** is a security research toolkit focused on analyzing cleartext credential persistence within Microsoft Edge process memory. The project demonstrates how credentials protected by front-end UI mechanisms (Windows Hello, biometrics, password reveal restrictions, etc.) may still transiently exist in readable process memory during runtime.

This raises a critical question: <b><i>what is Microsoft Edge actually protecting?</i></b> Why is the user required to enter a password on the front end to unlock their stored credentials <b>when an attacker can simply extract them in clear text from memory</b>?

The toolkit provides both: Live in-memory inspection & Offline forensic dump analysis for defensive research, memory forensics, and browser security auditing.

> [!CAUTION]
> This project is intended strictly for authorized security auditing, memory forensics research, and educational purposes. It is designed to demonstrate the security implications of transient cleartext credential exposure within application memory. Any unauthorized use against systems, accounts, or environments without explicit permission is strictly prohibited.  The author assumes no responsibility or liability for any misuse, damage, legal consequences, or unauthorized activities arising from the use of this project.

## Attack Paths

| Path | Method | Workflow | Result |
|---|---|---|---|
| **Path Alpha** | **Live In-Memory Extraction** | `EdgeSnapper.cpp` locates the target `msedge.exe` process, acquires a read handle, creates a PSS snapshot context, scans committed RW memory regions with regex-based parsing, and prints matching credential patterns directly to the console | ✅ No dump file written to disk |
| **Path Beta** | **Disk Dump + Offline Parsing** | `EdgeSnapperOnDisk.cpp` snapshots the Edge process and writes a full-memory `.dmp` using `MiniDumpWriteDump`. The resulting dump is then processed by the PowerShell parser `credHarvester.ps1` for offline extraction and filtering | ✅ Persistent forensic artifact for post-analysis |


## Suite Components

| Component | Language | Operation Type | Description |
|---|---|---|---|
| **EdgeSnapper** | C++ | Live RAM Scanner | Enumerates the target process, captures a point-in-time memory snapshot using `PssCaptureSnapshot`, walks virtual address regions via `PssWalkSnapshot`, and heuristically scans committed writable memory for credential-like plaintext strings. |
| **EdgeSnapperOnDisk** | C++ | Memory Dumper | Creates a full-process memory dump using `MiniDumpWriteDump(MiniDumpWithFullMemory)` after establishing a stable snapshot context |
| **credHarvester** | PowerShell | Offline Dump Parser | Loads the `.dmp` into memory using .NET file handling, applies regex extraction logic, removes telemetry noise, and deduplicates recovered credential artifacts |

> [!TIP]
> ```cpp
> // To compile on Linux:
> x86_64-w64-mingw32-g++ edgeSnapper.cpp -o edgeSnapper.exe -static -static-libgcc -static-libstdc++ -ldbghelp -lpsapi
> ```

## Snapshotting Strategy

Both native utilities utilize ```PssCaptureSnapshot()``` to stabilize process state before memory inspection or dumping.

This helps reduce:
- Torn reads
- Race conditions
- Inconsistent memory regions
- Active allocation corruption during scanning

#

> [!NOTE]
> This project is a proof of concept (PoC) and is intended primarily for research and educational purposes. Users are encouraged to modify and fine-tune it according to their specific needs.
>
> Contributions, issues, and merge requests are welcome, but all submissions are subject to review before acceptance.
>
> Please note that the codebase is not fully optimized. Some filtering mechanisms are currently word-based and may omit certain results. As such, this project should not be considered a fully reliable or comprehensive solution for detecting or displaying all possible results.

#
Inspired by [the original research.](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper)
