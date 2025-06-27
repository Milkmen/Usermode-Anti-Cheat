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

#define SUSPICIOUS_ACCESS_MASK (PROCESS_VM_WRITE)

#include <wintrust.h>
#include <Softpub.h>

#pragma comment(lib, "wintrust")

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
    trustData.dwStateAction = 0;
    trustData.hWVTStateData = NULL;
    trustData.dwProvFlags = 0;
    trustData.dwUIContext = 0;

    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

    return (status == ERROR_SUCCESS);
}

static const wchar_t* whitelist_paths[] = {
    L"C:\\Windows\\System32\\csrss.exe",
    L"C:\\Windows\\System32\\smss.exe",
    L"C:\\Windows\\System32\\wininit.exe",
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

static inline bool _umac_check_suspicious_handles()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return false;

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
        return false;

    ULONG bufferSize = 0x10000;
    PBYTE buffer = (PBYTE)malloc(bufferSize);
    if (!buffer)
        return false;

    NTSTATUS status;
    do {
        status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &bufferSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            free(buffer);
            buffer = (PBYTE)malloc(bufferSize);
            if (!buffer)
                return false;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return false;
    }

    SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
    DWORD currentPid = GetCurrentProcessId();

    SYSTEM_PROCESS_INFORMATION* processList = _umac_query_process_list();

    for (ULONG i = 0; i < handleInfo->HandleCount; ++i) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];

        if (handle.ProcessId < 5)
            continue;

        if (handle.ObjectTypeNumber == 7 && handle.ProcessId != currentPid &&
            (handle.GrantedAccess & SUSPICIOUS_ACCESS_MASK)) {

            // Try OpenProcess first
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handle.ProcessId);
            if (hProcess)
            {
                wchar_t path[MAX_PATH] = { 0 };
                DWORD pathSize = MAX_PATH;

                if (QueryFullProcessImageNameW(hProcess, 0, path, &pathSize))
                {
                    if (is_whitelisted_process_path(path) || _umac_file_signed(path))
                    {
                        CloseHandle(hProcess);
                        continue;  // skip this handle, it's whitelisted
                    }

                    // Convert wchar_t path to char for printf (simple ASCII assumption)
                    char cpath[MAX_PATH];
                    WideCharToMultiByte(CP_UTF8, 0, path, -1, cpath, MAX_PATH, NULL, NULL);

                    printf("UMAC: Suspicious handle from process PID=%lu: %s\n", handle.ProcessId, cpath);
                }
                else
                {
                    continue;
                }

                CloseHandle(hProcess);
            }
            else
            {
                continue;
            }

            if (processList)
                free(processList);

            free(buffer);
            return true;
        }
    }

    if (processList)
        free(processList);
    free(buffer);
    return false;
}

#endif

#endif