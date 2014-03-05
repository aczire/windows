/**
 * Filename: client-acl.cpp
 *
 * Try open shared section and report error code.
 */

#define WIN32_LEAN_AND_MEAN
#include "common.h"
#include <stdio.h>
#include <windows.h>
#include <Lmcons.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")

inline VOID WINAPI
PrintErrorCode(DWORD errCode)
{
    switch (errCode) {
        case ERROR_ACCESS_DENIED:
            _putts(_T("ACCESS DENIED"));
            break;
            
        default:
            _tprintf(_T("ERROR CODE = %u\n"), errCode);
    }
}

int
_tmain(int argc, TCHAR *argv[])
{
    TCHAR userName[UNLEN+1];
    DWORD dwTemp = sizeof(userName)/sizeof(TCHAR);
    
    if (FALSE == GetUserName(userName, &dwTemp)) {
        return (GetLastError());
    }
    
    _tprintf(_T("Current user: %s\n"), userName);
    _tprintf(_T("Open section \"%s\" with WRITE+READ permissions: "), kSectionName);
    
    // Try open with WRITE and READ permissions
    dwTemp = FILE_MAP_READ | FILE_MAP_WRITE;
    HANDLE hSection = OpenFileMapping(
        dwTemp,
        FALSE,
        kSectionName
    );

    if (nullptr != hSection) {
        _putts(_T("SUCCESS"));
    } else {
        // Try open with only READ permission
        PrintErrorCode(GetLastError());
        _tprintf(_T("Open section \"%s\" with READ permission: "), kSectionName);
        dwTemp = FILE_MAP_READ;
        hSection = OpenFileMapping(
            dwTemp,
            FALSE,
            kSectionName
        );
        if (nullptr != hSection) {
            _putts(_T("SUCCESS"));
        } else {
            PrintErrorCode(GetLastError());
        }
    }
    
    if (nullptr != hSection) {
        PBYTE pData = (PBYTE)MapViewOfFile(
            hSection,
            dwTemp,
            0,
            0,
            0
        );
        
        // Simulate working process
        _tprintf(_T("Do some work."));
        for (DWORD i = 0; i < 3; ++i) {
            Sleep(1000);
            _puttchar(_T('.'));
        }
        _puttchar(_T('\n'));
        
        // Clean resources
        UnmapViewOfFile(pData);
        CloseHandle(hSection);
        
        SetLastError(ERROR_SUCCESS);
    }
    
    return (GetLastError());
}
