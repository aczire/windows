/**
 * Filename: server-acl.cpp
 *
 * Creates shared section with non-default permissions.
 */
#define WIN32_LEAN_AND_MEAN
#include "common.h"
#include <stdio.h>
#include <windows.h>
#include <sddl.h>
#include <Strsafe.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")

// Signal state of this event tells that Ctrl+C or Ctrl+Break was pressed.
HANDLE gExitEvent = nullptr;

///
/// <summary>Function returns the string representation of a security identifier (SID)
/// fot the specific user, i.e. "S-R-I-S-S..."
/// </summary>
/// <param name="userName">String which contains the user name on the local computer.</param>
/// <param name="StringSid">Function writes in this buffer SID string</param>
/// <param name="StringSidLength">Length in TCHARs of the StringSid buffer, including 
/// the terminating null character.</param>
///
BOOL WINAPI
GetStringSidByUserName(
    _In_  PCTSTR userName,
    _Out_ PTSTR  StringSid,
    _In_  DWORD  StringSidLength
)
{
    PSID  userSid    = nullptr;
    PTSTR SidBuffer  = nullptr;
    PTSTR domainName = nullptr;
    DWORD sidSize    = 0;
    DWORD domainSize = 0;
    BOOL  isOk       = FALSE;
    SID_NAME_USE sidNameUse;
    
    __try {
        if (nullptr == StringSid) __leave;
        isOk = LookupAccountName(
            nullptr,
            userName,
            userSid,
            &sidSize,
            domainName,
            &domainSize,
            &sidNameUse
        );
        if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) __leave;
        
        userSid = (PSID)LocalAlloc(LMEM_FIXED, sidSize);
        // Note: Although we don't need the name of the domain where the account name is found
        // we still need allocate the space for the buffer, because of LookupAccountName
        // doesn't fill sidNameUse variable.
        domainName = (PTSTR)LocalAlloc(LMEM_FIXED, domainSize * sizeof(TCHAR));
        if (nullptr == userSid || nullptr == domainName) __leave;

        isOk = LookupAccountName(
            nullptr,
            userName,
            userSid,
            &sidSize,
            domainName,
            &domainSize,
            &sidNameUse
        );
        if (FALSE == isOk || SidTypeUser != sidNameUse) __leave;
        
        isOk = ConvertSidToStringSid(userSid, &SidBuffer);
        if (FALSE == isOk) __leave;
        
        if (StringSidLength < LocalSize(SidBuffer)) __leave;
        CopyMemory(StringSid, SidBuffer, LocalSize(SidBuffer));
        
        isOk = TRUE;
    } __finally {
        if (userSid) {
            LocalFree(userSid);
        }
        if (domainName) {
            LocalFree(domainName);
        }
        if (SidBuffer) {
            LocalFree(SidBuffer);
        }
    }
    
    return (isOk);
}

///
/// <summary>Function returns security descriptor (SD) for shared section.
/// This SD contains the following ACE:
///   * Denied access: anonymous logon (SDDL_ANONYMOUS) (case 1);
///   * Denied access: any member of Guests (SDDL_BUILTIN_GUESTS) (case 2);
///   * Denied access: any member of Power Users (SDDL_POWER_USERS) (case 3);
///   * Allow access for any operations: all local administrators (SDDL_LOCAL_ADMIN) (case 4);
///   * Allow access for read: all built-in users (SDDL_BUILTIN_USERS) (case 5);
///   * Allow access for read and write: specific user "Bob" (case 6).
/// </summary>
///
PSID WINAPI
CreateSecurityDescriptorForSharedSection()
{
    // Specify the user with read and write access
    const TCHAR kUserName[] = _T("Bob");
    // ACE Strings has the following format:
    // ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
    // More info: http://msdn.microsoft.com/en-us/library/windows/desktop/aa374928(v=vs.85).aspx
    const TCHAR kACEString[] = _T("")
        _T("(D;NP;GA;;;AN)")  // case 1
        _T("(D;NP;GA;;;BG)")  // case 2
        _T("(D;NP;GA;;;PU)")  // case 3
        _T("(A;NP;GA;;;BA)")  // case 4
        _T("(A;NP;GR;;;BU)")  // case 5
    _T("");
    PSID    sid = nullptr;
    BOOL    ret = FALSE;
    HRESULT hResult;
    TCHAR   stringSid[100];
    TCHAR   buf[MAX_PATH];
    
    // Build string for ConvertStringSecurityDescriptorToSecurityDescriptor function
    ret = GetStringSidByUserName(kUserName, stringSid, sizeof(stringSid));
    if (FALSE == ret) {
        return (sid);
    }
    hResult = StringCchPrintf(
        buf,
        sizeof(buf),
        _T("D:P%s(A;NP;GRGW;;;%s)"), kACEString, stringSid
    );
    if (FAILED(hResult)) {
        return (sid);
    }
    
    ret = ConvertStringSecurityDescriptorToSecurityDescriptor(
        buf,
        SDDL_REVISION_1,
        &sid,
        nullptr
    );
    
    return (sid);
}

///
/// <summary>Returns the page size in bytes.</summary>
///
DWORD WINAPI
GetPageSize()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (si.dwPageSize);
}

///
/// <summary>Function creates namep shared section with specific permissions and
/// waits for clients.</summary>
///
VOID WINAPI
SharedSectionWatchDog()
{
    const DWORD kPageSize = GetPageSize();
    const PSID  sid       = CreateSecurityDescriptorForSharedSection();
    
    HANDLE hSection = nullptr;
    PBYTE  pData    = nullptr;
    BOOL   isOk     = FALSE;
    SECURITY_ATTRIBUTES sa;
    
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = sid;
    
    __try {
        if (nullptr == sid) __leave;
        
        hSection = CreateFileMapping(
            INVALID_HANDLE_VALUE,
            &sa,
            PAGE_READWRITE,
            0,
            kPageSize,
            kSectionName
        );
        if (nullptr == hSection) __leave;
        
        pData = (PBYTE)MapViewOfFile(
            hSection,
            FILE_MAP_READ|FILE_MAP_WRITE,
            0,
            0,
            0
        );
        if (nullptr == pData) __leave;
        
        SecureZeroMemory(pData, kPageSize);
        _tprintf(_T("Clients can use shared section \"%s\"\n"), kSectionName);
        _putts(_T("Press Ctrl+C to exit"));
        
        if (WAIT_OBJECT_0 != WaitForSingleObject(gExitEvent, INFINITE)) __leave;
        
        isOk = TRUE;
    } __finally {
        if (pData) {
            UnmapViewOfFile(pData);
        }
        if (hSection) {
            CloseHandle(hSection);
        }
        if (sid) {
            LocalFree(sid);
        }
    }
    
    if (isOk) {
        SetLastError(ERROR_SUCCESS);
    }
}

///
/// <summary>Handler function that handle Ctrl+C and Ctrl+Break signals.</summary>
///
BOOL WINAPI
CtrlHandler(DWORD dwCtrlType)
{
    SetEvent(gExitEvent);
    return (TRUE);
}

int
_tmain(int argc, TCHAR *argv[])
{
    gExitEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (nullptr == gExitEvent) {
        return (GetLastError());
    }
    // register handler for Ctrl+C, Ctrl+Break
    if (0 == SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        return (GetLastError());
    }
    
    SharedSectionWatchDog();
    
    return (GetLastError());
}
