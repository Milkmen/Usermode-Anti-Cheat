#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Find the PID of the process by name
DWORD FindProcessId(const char* processName)
{
    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snapshot, &processEntry))
    {
        do
        {
            if (_stricmp(processEntry.szExeFile, processName) == 0)
            {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

int main()
{
    const char* targetProcessName = "Usermode-Anti-Cheat.exe";
    DWORD targetPid = FindProcessId(targetProcessName);
    if (targetPid == 0)
    {
        printf("Could not find process '%s'. Is it running?\n", targetProcessName);
        return 1;
    }

    printf("Found %s with PID %lu\n", targetProcessName, targetPid);

    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE, FALSE, targetPid);
    if (!hProcess)
    {
        printf("Failed to open process with PROCESS_VM_WRITE access. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("Successfully opened %s with PROCESS_VM_WRITE access. Your detector should flag this.\n", targetProcessName);

    Sleep(60000);  // Keep handle open for 60 seconds

    CloseHandle(hProcess);
    return 0;
}
