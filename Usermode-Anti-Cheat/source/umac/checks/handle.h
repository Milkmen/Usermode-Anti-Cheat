#ifndef CHECK_HANDLE_H
#define CHECK_HANDLE_H

#ifdef _WIN32

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

#pragma pack(push, 1)
typedef struct _SYSTEM_HANDLE {
    ULONG       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION;

#pragma pack(pop)

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef SystemProcessInformation
#define SystemProcessInformation 5
#endif

#include <wintrust.h>
#include <Softpub.h>

#pragma comment(lib, "wintrust.lib")

static bool _umac_file_signed(LPCWSTR filePath)
{
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;  // Fixed: was 0
    trustData.hWVTStateData = NULL;
    trustData.dwProvFlags = WTD_SAFER_FLAG;  // Fixed: was 0
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;  // Fixed: was 0

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // Clean up the state data
    if (trustData.hWVTStateData != NULL)
    {
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &policyGUID, &trustData);
    }

    // Check for various success conditions
    switch (status)
    {
    case ERROR_SUCCESS:
        return true;
    case TRUST_E_NOSIGNATURE:
        // File is not signed
        return false;
    case TRUST_E_EXPLICIT_DISTRUST:
        // File is signed but signature is not trusted
        return false;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        // File is signed but signer is not trusted
        return false;
    case CRYPT_E_SECURITY_SETTINGS:
        // Security settings prevent verification
        return false;
    default:
        // Other error occurred
        return false;
    }
}

static const wchar_t* whitelist_paths[] = {
    L"C:\\Windows\\System32\\csrss.exe",
    L"C:\\Windows\\System32\\smss.exe",
    L"C:\\Windows\\System32\\wininit.exe",
    L"C:\\Windows\\System32\\ctfmon.exe",
    L"C:\\Windows\\System32\\sihost.exe",
    L"C:\\Windows\\System32\\oobe\\UserOOBEBroker.exe",
    NULL
};

static bool is_whitelisted_process_path(const wchar_t* procPath)
{
    for (int i = 0; whitelist_paths[i] != NULL; ++i)
    {
        // Compare length first for a quick fail
        size_t lenWhitelist = wcslen(whitelist_paths[i]);
        size_t lenProcPath = wcslen(procPath);
        if (lenWhitelist != lenProcPath)
            continue;

        // Case-insensitive compare full path
        if (_wcsicmp(procPath, whitelist_paths[i]) == 0)
            return true;
    }
    return false;
}

static inline SYSTEM_PROCESS_INFORMATION* _umac_query_process_list()
{
    ULONG bufferSize = 0x10000;
    NTSTATUS status;
    SYSTEM_PROCESS_INFORMATION* buffer = NULL;

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
        return NULL;

    do {
        buffer = (SYSTEM_PROCESS_INFORMATION*)malloc(bufferSize);
        if (!buffer)
            return NULL;

        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            buffer = NULL;
            bufferSize *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

static inline const wchar_t* _umac_get_process_name_by_pid(SYSTEM_PROCESS_INFORMATION* list, DWORD pid)
{
    SYSTEM_PROCESS_INFORMATION* entry = list;
    while (entry) {
        if ((DWORD)(ULONG_PTR)entry->UniqueProcessId == pid) {
            if (entry->ImageName.Length > 0)
                return entry->ImageName.Buffer;
            else
                return L"[System Process]";
        }

        if (entry->NextEntryOffset == 0)
            break;

        entry = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)entry + entry->NextEntryOffset);
    }
    return L"[Unknown Process]";
}

#define SUSPICIOUS_ACCESS_MASK (PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE)

static inline bool _umac_check_suspicious_handles()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("UMAC: Failed to get ntdll handle\n");
        return false;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("UMAC: Failed to get NtQuerySystemInformation address\n");
        return false;
    }

    ULONG bufferSize = 0x100000;  // Start with 1MB buffer
    PBYTE buffer = (PBYTE)malloc(bufferSize);
    if (!buffer) {
        printf("UMAC: Failed to allocate initial buffer\n");
        return false;
    }

    NTSTATUS status;
    int retries = 0;
    do {
        status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            bufferSize += 0x50000;  // Add 320KB each retry
            buffer = (PBYTE)malloc(bufferSize);
            if (!buffer) {
                printf("UMAC: Failed to allocate buffer of size %lu\n", bufferSize);
                return false;
            }
            printf("UMAC: Buffer too small, retrying with size %lu\n", bufferSize);
        }
        retries++;
    } while (status == STATUS_INFO_LENGTH_MISMATCH && retries < 5);

    if (!NT_SUCCESS(status)) {
        printf("UMAC: NtQuerySystemInformation failed with status 0x%08X after %d retries\n", status, retries);
        free(buffer);
        return false;
    }

    SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
    DWORD currentPid = GetCurrentProcessId();

    bool foundSuspicious = false;

    for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];

        // Skip system/idle processes
        if (handle.ProcessId <= 4)
            continue;

        // Skip our own process
        if (handle.ProcessId == currentPid)
            continue;

        // Check for process object types (common values across Windows versions)
        if (handle.ObjectTypeNumber < 5 || handle.ObjectTypeNumber > 8)
            continue;

        // Check if this handle has any suspicious access rights
        if (!(handle.GrantedAccess & SUSPICIOUS_ACCESS_MASK))
            continue;

        // Now we need to determine if this handle points to OUR process
        // We'll do this by trying to open the same process and comparing some properties
        HANDLE hTargetProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handle.ProcessId);
        if (!hTargetProcess) {
            continue;
        }

        // Get the process path for logging and whitelist checking
        wchar_t processPath[MAX_PATH] = { 0 };
        DWORD pathSize = MAX_PATH;

        if (!QueryFullProcessImageNameW(hTargetProcess, 0, processPath, &pathSize)) {
            CloseHandle(hTargetProcess);
            continue;
        }

        // Convert to char for printing
        char cProcessPath[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, processPath, -1, cProcessPath, MAX_PATH, NULL, NULL);

        // Check if this process is whitelisted
        if (is_whitelisted_process_path(processPath)) {
            CloseHandle(hTargetProcess);
            continue;
        }

        // Check code signing
        if (_umac_file_signed(processPath)) {
            CloseHandle(hTargetProcess);
            continue;
        }

        // At this point, we have a suspicious handle from an unsigned process
        // But we still need to verify it's actually a handle to OUR process

        // Simple heuristic: if a process has a handle with write access to ANY process
        // and it's not whitelisted/signed, flag it as suspicious
        // (More sophisticated detection would verify the handle target)

        if (handle.GrantedAccess & (PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD)) {
            printf("UMAC: SUSPICIOUS HANDLE DETECTED!\n");
            printf("UMAC: Process: %s (PID: %lu)\n", cProcessPath, handle.ProcessId);
            printf("UMAC: Access Rights: 0x%08X\n", handle.GrantedAccess);
            printf("UMAC: Object Type: %d\n", handle.ObjectTypeNumber);

            foundSuspicious = true;
        }

        CloseHandle(hTargetProcess);
    }

    free(buffer);
    return foundSuspicious;
}


// Alternative approach - enumerate handles to our specific process
static inline bool _umac_check_handles_to_current_process()
{
    DWORD currentPid = GetCurrentProcessId();

    // Get a snapshot of all processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);

    bool foundSuspicious = false;

    if (Process32First(snapshot, &pe)) {
        do {
            // Skip system processes and ourselves
            if (pe.th32ProcessID <= 4 || pe.th32ProcessID == currentPid)
                continue;

            // Try to open this process to see if it has handles to us
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProcess)
                continue;

            // Try to duplicate a handle to our process from this process
            // This is a way to detect if the process has a handle to us
            HANDLE hDuplicated = NULL;
            if (DuplicateHandle(hProcess, (HANDLE)currentPid, GetCurrentProcess(),
                &hDuplicated, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

                printf("UMAC: Process %s (PID: %lu) has a handle to our process!\n",
                    pe.szExeFile, pe.th32ProcessID);

                // Check if this process should be trusted
                wchar_t wProcessName[MAX_PATH];
                MultiByteToWideChar(CP_UTF8, 0, pe.szExeFile, -1, wProcessName, MAX_PATH);

                if (!is_whitelisted_process_path(wProcessName) && !_umac_file_signed(wProcessName)) {
                    printf("UMAC: SUSPICIOUS PROCESS DETECTED: %s\n", pe.szExeFile);
                    foundSuspicious = true;
                }

                CloseHandle(hDuplicated);
            }

            CloseHandle(hProcess);

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return foundSuspicious;
}

// Updated main checking function to use both methods
static inline bool _umac_check_handles()
{
    // Method 1: System handle enumeration
    bool method1Result = _umac_check_suspicious_handles();

    // Method 2: Process enumeration approach  
    bool method2Result = _umac_check_handles_to_current_process();

    return method1Result || method2Result;
}

#endif

#endif