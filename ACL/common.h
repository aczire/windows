/**
 * Filename: common.h
 *
 * Some common constants and functions
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <sddl.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")


const TCHAR kSectionName[] = _T("Global\\TestSharedSection");

///
/// <summary>Function returns the string representation of a security identifier (SID)
/// fot the specific user, i.e. "S-R-I-S-S..."
/// </summary>
/// <param name="userName">String which contains the user name on the local computer.</param>
/// <param name="stringSid">Function writes in this buffer SID string</param>
/// <param name="stringSidLength">Length in TCHARs of the StringSid buffer, including 
/// the terminating null character.</param>
///
BOOL WINAPI
GetStringSidByUserName(
    _In_z_                        PCTSTR userName,
    _Out_writes_(stringSidLength) PTSTR  stringSid,
    _In_                          DWORD  stringSidLength
)
{
    PSID  userSid    = nullptr;
    PTSTR sidBuffer  = nullptr;
    PTSTR domainName = nullptr;
    DWORD sidSize    = 0;
    DWORD domainSize = 0;
    BOOL  isOk       = FALSE;
    SID_NAME_USE sidNameUse;
    
    __try {
        if (nullptr == stringSid) __leave;
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
        
        isOk = ConvertSidToStringSid(userSid, &sidBuffer);
        if (FALSE == isOk) __leave;
        
        if (stringSidLength * sizeof(TCHAR) < LocalSize(sidBuffer)) __leave;
        CopyMemory(stringSid, sidBuffer, LocalSize(sidBuffer));
        
        isOk = TRUE;
    } __finally {
        if (userSid) {
            LocalFree(userSid);
        }
        if (domainName) {
            LocalFree(domainName);
        }
        if (sidBuffer) {
            LocalFree(sidBuffer);
        }
    }
    
    return (isOk);
}

///
/// <summary>Function returns the full user name of a security identifier (SID).
/// The full user name consists of two parts: domain name and user name. If function can't
/// retrieve the user name it simply returns the string representation of the SID.
/// </summary>
/// <param name="userSid">The source SID.</param>
/// <param name="fullName">Function writes in this buffer full user name string</param>
/// <param name="fullNameLength">Length in TCHARs of the fullName buffer, including 
/// the terminating null character.</param>
///
BOOL WINAPI
GetFullUserNameBySid(
    _In_                         PSID  userSid,
    _Out_writes_(fullNameLength) PTSTR fullName,
    _In_                         DWORD fullNameLength
)
{
    PTSTR userName     = nullptr;
    PTSTR domainName   = nullptr;
    DWORD userLength   = 0;
    DWORD domainLength = 0;
    BOOL  isOk         = FALSE;
    HRESULT hResult;
    SID_NAME_USE peUse;
    
    __try {
        isOk = LookupAccountSid(
            nullptr,
            userSid,
            nullptr,
            &userLength,
            nullptr,
            &domainLength,
            &peUse
        );
        if (ERROR_NONE_MAPPED == GetLastError()) {
            // user doesn't have name
            PTSTR StringSid = nullptr;
            isOk = ConvertSidToStringSid(userSid, &StringSid);
            if (FALSE == isOk) __leave;
            
            hResult = StringCchPrintf(
                fullName,
                fullNameLength,
                _T("%s"), StringSid
            );
            LocalFree(StringSid);
            
            if (SUCCEEDED(hResult)) isOk = TRUE;
            
            __leave;
        } 
        if (ERROR_INSUFFICIENT_BUFFER != GetLastError()) __leave;
        
        userName   = (PTSTR)LocalAlloc(LMEM_FIXED, userLength   * sizeof(TCHAR));
        domainName = (PTSTR)LocalAlloc(LMEM_FIXED, domainLength * sizeof(TCHAR));
        if (nullptr == userName || nullptr == domainName) __leave;
        
        isOk = LookupAccountSid(
            nullptr,
            userSid,
            userName,
            &userLength,
            domainName,
            &domainLength,
            &peUse
        );
        if (FALSE == isOk) __leave;
        
        hResult = StringCchPrintf(
            fullName,
            fullNameLength,
            _T("%s\\%s"), domainName, userName
        );
        if (FAILED(hResult)) __leave;
        
        isOk = TRUE;
    } __finally {
        if (domainName) {
            LocalFree(domainName);
        }
        if (userName) {
            LocalFree(userName);
        }
    }
    
    return (isOk);
}
