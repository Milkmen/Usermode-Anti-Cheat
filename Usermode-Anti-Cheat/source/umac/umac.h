#ifndef USERMODE_AC_H
#define USERMODE_AC_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
	HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

#endif

#define UMAC_CHECK_DEBUGGER (1 << 0)
#define UMAC_CHECK_HANDLE	(1 << 1)

#include "checks/debug.h"
#include "checks/handle.h"

static inline void umac_initialize()
{

}

static inline uint16_t umac_check_regular()
{
	uint16_t vl = 0;

#ifndef UMAC_NO_DEBUG_CHECKS
	if(_umac_debugger_present()) vl |= UMAC_CHECK_DEBUGGER;
#endif
	return vl;
}

static inline uint16_t umac_check_intermittent()
{
	uint16_t vl = 0;
	#ifndef UMAC_NO_HANDLE_CHECKS
		if (_umac_check_handles()) vl |= UMAC_CHECK_HANDLE;
	#endif
	return vl;
}

static inline void umac_shutdown()
{
	
}

#endif