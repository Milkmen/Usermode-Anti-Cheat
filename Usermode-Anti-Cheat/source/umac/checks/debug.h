#ifndef CHECK_DEBUG_H
#define CHECK_DEBUG_H

typedef struct _PEB_ {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG Reserved3[2];
    ULONG NtGlobalFlag;
} PEB_;

static inline bool _umac_debugger_present()
{
#ifdef _WIN32
    // Check 1
    if (IsDebuggerPresent())
        return true;

    // Check 2
    BOOL bDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent);
    if (bDebuggerPresent)
        return true;

    // Check 3
#ifdef _M_X64
    PEB_* peb = (PEB_*)__readgsqword(0x60);
#else
    PEB_* peb = (PEB_*)__readfsdword(0x30);
#endif
    if (peb->BeingDebugged)
        return true;
#endif
    return false;
}

#endif