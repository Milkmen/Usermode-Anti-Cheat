#ifndef CHECK_HANDLE_H
#define CHECK_HANDLE_H

#ifdef _WIN32

#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h> // For PROCESSENTRY32W and CreateToolhelp32Snapshot
#include <stdio.h>    // For printf
#include <wintrust.h> // For WinVerifyTrust
#include <Softpub.h>  // For WINTRUST_ACTION_GENERIC_VERIFY_V2
#pragma comment(lib, "wintrust.lib")

// Define necessary NTSTATUS codes and information classes if not already defined
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation 16 // Used with NtQuerySystemInformation
#endif

#ifndef ObjectTypeInformation
#define ObjectTypeInformation 2 // Used with NtQueryObject
#endif

#ifndef DUPLICATE_SAME_ACCESS
#define DUPLICATE_SAME_ACCESS 0x00000002 // Used with NtDuplicateObject
#endif

// Typedefs for Native API functions
typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI* pNtQueryObject)(
	HANDLE Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef NTSTATUS(WINAPI* pNtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Options
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
	SYSTEM_HANDLE Handles[1]; // Flexible array member
} SYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;
#pragma pack(pop)

// Whitelist for specific executable paths (exact matches)
static const wchar_t* whitelist_paths[] = {
	L"C:\\Program Files\\Windows Defender\\NisSrv.exe",
	NULL
};

// Whitelist for system directories (prefix matches)
static const wchar_t* whitelisted_directories[] = {
	L"C:\\Windows\\System32\\",
	L"C:\\Windows\\SysWOW64\\",
	L"C:\\Program Files\\",
	L"C:\\Program Files (x86)\\",
	L"C:\\Windows\\SystemApps\\",
	NULL
};


static bool _umac_file_signed(LPCWSTR filePath)
{
	WINTRUST_FILE_INFO fileInfo = { 0 };
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = filePath;

	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA trustData = { 0 };
	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.dwUIChoice = WTD_UI_NONE;         // Do not display any UI
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE; // No revocation check for performance
	trustData.dwUnionChoice = WTD_CHOICE_FILE;  // Verify a file
	trustData.pFile = &fileInfo;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY; // Verify the signature
	trustData.dwProvFlags = WTD_SAFER_FLAG;     // Apply SAFER policy checks
	trustData.dwUIContext = WTD_UICONTEXT_EXECUTE; // Context for executing a file

	LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);

	if (trustData.hWVTStateData != NULL) 
	{
		trustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &policyGUID, &trustData);
	}

	return (status == ERROR_SUCCESS);
}

static bool is_whitelisted_process_path(const wchar_t* procPath)
{
	if (!procPath) return false;

	// First, check for exact matches in the specific executable whitelist
	for (int i = 0; whitelist_paths[i] != NULL; ++i) {
		if (_wcsicmp(procPath, whitelist_paths[i]) == 0) {
			return true;
		}
	}

	for (int i = 0; whitelisted_directories[i] != NULL; ++i) 
	{
		size_t dir_len = wcslen(whitelisted_directories[i]);
		if (_wcsnicmp(procPath, whitelisted_directories[i], dir_len) == 0) 
		{
			return true;
		}
	}

	return false;
}

static pNtQuerySystemInformation pNtQuerySystemInformation_ptr = NULL;
static pNtQueryObject pNtQueryObject_ptr = NULL;
static pNtDuplicateObject pNtDuplicateObject_ptr = NULL;

static inline void _umac_init_ntdll_funcs()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) 
	{
		printf("UMAC: Error: Could not get handle to ntdll.dll!\n");
		return;
	}

	pNtQuerySystemInformation_ptr = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	pNtQueryObject_ptr = (pNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
	pNtDuplicateObject_ptr = (pNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");

	if (!pNtQuerySystemInformation_ptr || !pNtQueryObject_ptr || !pNtDuplicateObject_ptr) 
	{
		printf("UMAC: Error: Failed to get one or more NTDLL function addresses.\n");
	}
}

#define SUSPICIOUS_ACCESS_MASK (PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | \
                               PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION | \
                               PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_SET_QUOTA | \
                               PROCESS_SET_INFORMATION | PROCESS_VM_WRITE | PROCESS_SET_LIMITED_INFORMATION)

static DWORD _umac_get_handle_target_pid(HANDLE hProcess, HANDLE hRemoteHandle)
{
	if (!pNtDuplicateObject_ptr) 
	{
		_umac_init_ntdll_funcs(); // Ensure functions are loaded
		if (!pNtDuplicateObject_ptr) return 0;
	}

	HANDLE hDuplicated = NULL;
	NTSTATUS status = pNtDuplicateObject_ptr(
		hProcess, hRemoteHandle, GetCurrentProcess(),
		&hDuplicated, 0, 0, DUPLICATE_SAME_ACCESS
	);

	if (!NT_SUCCESS(status)) 
	{
		// printf("UMAC: NtDuplicateObject failed with status 0x%X\n", status);
		return 0;
	}

	DWORD targetPid = GetProcessId(hDuplicated);
	CloseHandle(hDuplicated);

	return targetPid;
}

static inline bool _umac_check_handles_to_self()
{
	if (!pNtQuerySystemInformation_ptr || !pNtDuplicateObject_ptr || !pNtQueryObject_ptr) 
	{
		_umac_init_ntdll_funcs();
		if (!pNtQuerySystemInformation_ptr || !pNtDuplicateObject_ptr || !pNtQueryObject_ptr) return false;
	}

	ULONG bufferSize = 0x100000;
	PBYTE buffer = NULL;
	NTSTATUS status;
	int retries = 0;
	const int MAX_RETRIES = 5;

	UCHAR processObjectTypeIndex = 7;

	do 
	{
		buffer = (PBYTE)realloc(buffer, bufferSize); // Use realloc to grow buffer
		if (!buffer) 
		{
			printf("UMAC: Error: Failed to allocate buffer for SYSTEM_HANDLE_INFORMATION.\n");
			return false;
		}

		status = pNtQuerySystemInformation_ptr(SystemHandleInformation, buffer, bufferSize, &bufferSize);

		if (status != STATUS_INFO_LENGTH_MISMATCH && !NT_SUCCESS(status)) 
		{
			printf("UMAC: Error: NtQuerySystemInformation failed with status 0x%X\n", status);
			free(buffer);
			return false;
		}
		retries++;
	}
	while (status == STATUS_INFO_LENGTH_MISMATCH && retries < MAX_RETRIES);

	if (!NT_SUCCESS(status)) 
	{
		printf("UMAC: Final Error: NtQuerySystemInformation failed after retries with status 0x%X\n", status);
		free(buffer);
		return false;
	}

	SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
	DWORD currentPid = GetCurrentProcessId();
	bool foundSuspicious = false;

	DWORD checkedProcesses[1024] = { 0 }; // Max 1024 unique PIDs
	int checkedCount = 0;

	for (ULONG i = 0; i < handleInfo->HandleCount; ++i) 
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];

		if (handle.ProcessId <= 4 || handle.ProcessId == currentPid) 
		{
			continue;
		}

		if (handle.ObjectTypeNumber != processObjectTypeIndex) 
		{
			continue;
		}

		bool alreadyChecked = false;
		for (int j = 0; j < checkedCount; j++) 
		{
			if (checkedProcesses[j] == handle.ProcessId) 
			{
				alreadyChecked = true;
				break;
			}
		}
		if (alreadyChecked) 
		{
			continue;
		}

		if (checkedCount < ARRAYSIZE(checkedProcesses)) 
		{
			checkedProcesses[checkedCount++] = handle.ProcessId;
		}
		else 
		{
			printf("UMAC: Warning: checkedProcesses array full, potential missed checks.\n");
		}

		if (!(handle.GrantedAccess & SUSPICIOUS_ACCESS_MASK)) 
		{
			continue;
		}

		HANDLE hOwnerProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
			FALSE, handle.ProcessId);
		if (!hOwnerProcess) 
		{
			continue;
		}

		DWORD targetPid = _umac_get_handle_target_pid(hOwnerProcess, (HANDLE)(uintptr_t)handle.Handle);

		if (targetPid == currentPid) 
		{
			wchar_t processPath[MAX_PATH] = { 0 };
			DWORD pathSize = MAX_PATH;

			if (QueryFullProcessImageNameW(hOwnerProcess, 0, processPath, &pathSize)) 
			{
				if (!is_whitelisted_process_path(processPath) && !_umac_file_signed(processPath)) 
				{
					foundSuspicious = true;
				}
			}
			else {
				printf("UMAC: Warning: Could not get process image name for PID %lu (Error: %lu)\n", handle.ProcessId, GetLastError());
			}
		}
		CloseHandle(hOwnerProcess);
	}

	free(buffer);
	return foundSuspicious;
}

static inline bool _umac_check_process_handles()
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) 
	{
		printf("UMAC: Error: CreateToolhelp32Snapshot failed (Error: %lu).\n", GetLastError());
		return false;
	}

	PROCESSENTRY32W pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32W);

	DWORD currentPid = GetCurrentProcessId();
	bool foundSuspicious = false;

	if (Process32FirstW(snapshot, &pe)) 
	{
		do 
		{
			if (pe.th32ProcessID <= 4 || pe.th32ProcessID == currentPid) 
			{
				continue;
			}

			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pe.th32ProcessID);
			if (!hProcess) 
			{
				continue; // Cannot open
			}

			HANDLE hTestHandle = NULL;

			if (DuplicateHandle(hProcess, GetCurrentProcess(), GetCurrentProcess(),
				&hTestHandle, SUSPICIOUS_ACCESS_MASK, FALSE, 0)) 
			{

				wchar_t processPath[MAX_PATH] = { 0 };
				DWORD pathSize = MAX_PATH;

				if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) 
				{
					if (!is_whitelisted_process_path(processPath) && !_umac_file_signed(processPath)) 
					{
						foundSuspicious = true;
					}
				}
				CloseHandle(hTestHandle); // Always close duplicated handle
			}
			CloseHandle(hProcess); // Always close the opened process handle
		} 
		while (Process32NextW(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return foundSuspicious;
}

static inline bool _umac_check_handles()
{
	_umac_init_ntdll_funcs();

	bool method1_result = _umac_check_handles_to_self();
	bool method2_result = _umac_check_process_handles();

	return method1_result || method2_result;
}

#endif

#endif