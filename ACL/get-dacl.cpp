/**
 * Filename: get-dacl.cpp
 *
 * Print DACL of the named kernel objects plus file.
 */
#define WIN32_LEAN_AND_MEAN
#include "common.h"
#include <windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <aclapi.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")


enum OBJECT_TYPE : SIZE_T {
    UNKNOWN_OBJECT = 0,
    EVENT_OBJECT,
    MUTEX_OBJECT,
    SEMAPHORE_OBJECT,
    FILE_MAPPING_OBJECT,
    JOB_OBJECT,
    WAITABLE_TIMER_OBJECT,
    NAMED_PIPE_OBJECT,
    MAIL_SLOT_OBJECT,
    FILE_OBJECT
};

///
/// <summary>Functions returns type and handle of the named kernel object. Supported
/// named objects:
///   * event;
///   * mutex;
///   * semaphore;
///   * shared section;
///   * job;
///   * waitable timer;
///   * pipe;
///   * mailslot;
///   * file.</summary>
/// <param name="objectName">String which contains name of the kernel object.</param>
/// <param name="hObject">Handle of the kernel object with name objectName or nullptr.</param>
///
OBJECT_TYPE WINAPI
GetObjectTypeByName(
    _In_z_ PCTSTR  objectName,
    _Out_  HANDLE* hObject
)
{
    typedef HANDLE (WINAPI *PTR_OPEN_FUNCTION)(DWORD, BOOL, PCTSTR);
    
    OBJECT_TYPE obType = UNKNOWN_OBJECT;
    const TCHAR kPrefixPipe[]     = _T("\\\\.\\pipe\\");
    const TCHAR kPrefixMailslot[] = _T("\\\\.\\mailslot\\");
    const PTR_OPEN_FUNCTION kOpenFunction[] = {
        OpenEvent,
        OpenMutex,
        OpenSemaphore,
        OpenFileMapping,
        OpenJobObject,
        OpenWaitableTimer
    };
    
    *hObject = nullptr;
    for (SIZE_T i = 0; i < _countof(kOpenFunction); ++i) {
        *hObject = kOpenFunction[i](READ_CONTROL, FALSE, objectName);
        if (nullptr != *hObject) {
            obType = (OBJECT_TYPE)(i + 1);
            break;
        }
    }
    if (nullptr == *hObject) {
        *hObject = CreateFile(objectName, READ_CONTROL, FILE_SHARE_READ|FILE_SHARE_WRITE, 
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (INVALID_HANDLE_VALUE == *hObject) {
            *hObject = nullptr;
        } else if (_T('\\') == objectName[0]) {
            if  (0 == StrCmpNI(objectName, kPrefixPipe, (sizeof(kPrefixPipe) - 1)/sizeof(TCHAR))) {
                // named pipe
                obType = NAMED_PIPE_OBJECT;
            } else if (0 == StrCmpNI(objectName, kPrefixMailslot, (sizeof(kPrefixMailslot) - 1)/sizeof(TCHAR))) {
                // mailslot
                obType = MAIL_SLOT_OBJECT;
            } else {
                // path to file in format "\\?\"
                obType = FILE_OBJECT;
            }
        } else {
            obType = FILE_OBJECT;
        }
    }
    
    return (obType);
}


///
/// <summary>Print out to the stdout the DACL of the named kernel object.</summary>
/// <param name="objectName">String which contains name of the kernel object.</param>
///
VOID WINAPI
PrintDACL(
    _In_z_ PTSTR objectName
)
{
    HANDLE      hObject;
    OBJECT_TYPE obType;
    DWORD       retValue;
    TCHAR       buf[MAX_PATH];
    PSID        pSidOwner = nullptr;
    PACL        pDacl     = nullptr;
    PSECURITY_DESCRIPTOR pSid = nullptr;
    PACCESS_ALLOWED_ACE  pAce = nullptr;
    
    obType = GetObjectTypeByName(objectName, &hObject);
    if (UNKNOWN_OBJECT == obType) {
        _ftprintf(stderr, _T("[-] GetObjectTypeByName: %u\n"), GetLastError());
        return;
    }
    
    retValue = GetSecurityInfo(hObject, SE_KERNEL_OBJECT, 
		DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION,
		&pSidOwner, nullptr, &pDacl, nullptr, &pSid
    );
    CloseHandle(hObject);
    if (ERROR_SUCCESS != retValue) {
        _ftprintf(stderr, _T("[-] GetSecurityInfo: %u\n"), GetLastError());
        return;
    }
    
    // print out object name and object type
    _tprintf(_T("Object name : %s\n"), objectName);
    _tprintf(_T("Object type : "));
    switch (obType) {
        case EVENT_OBJECT         : _putts(_T("Event")); break;
        case MUTEX_OBJECT         : _putts(_T("Mutex")); break;
        case SEMAPHORE_OBJECT     : _putts(_T("Semaphore")); break;
        case FILE_MAPPING_OBJECT  : _putts(_T("Shared Section")); break;
        case JOB_OBJECT           : _putts(_T("Job")); break;
        case WAITABLE_TIMER_OBJECT: _putts(_T("Waitable Timer")); break;
        case NAMED_PIPE_OBJECT    : _putts(_T("Named Pipe")); break;
        case MAIL_SLOT_OBJECT     : _putts(_T("Mailslot")); break;
        case FILE_OBJECT          : _putts(_T("File")); break;
    }
    
    // print out object owner
    if (FALSE == GetFullUserNameBySid(pSidOwner, buf, sizeof(buf)/sizeof(TCHAR))) {
        _ftprintf(stderr, _T("[-] GetFullUserNameBySid: %u\n"), GetLastError());
        return;
    }
    _tprintf(_T("Object owner: %s\n"), buf);
    
    // print out each ACE entry in DACL
    for (SIZE_T i = 0; i < pDacl->AceCount; ++i) {
        if (FALSE == GetAce(pDacl, i, (PVOID*)&pAce)) {
            _ftprintf(stderr, _T("[-] GetAce: %u\n"), GetLastError());
        }
        pSidOwner = &(pAce->SidStart);
        if (FALSE == GetFullUserNameBySid(pSidOwner, buf, sizeof(buf)/sizeof(TCHAR))) {
            _ftprintf(stderr, _T("[-] GetFullUserNameBySid: %u\n"), GetLastError());
        }
        switch (pAce->Header.AceType) {
            case ACCESS_ALLOWED_ACE_TYPE: _tprintf(_T("ALLOWED\n")); break;
            case ACCESS_DENIED_ACE_TYPE:  _tprintf(_T("DENIED\n")); break;
            default: _tprintf(_T("UNK\n"));
        }
        _tprintf(_T("  User         : %s\n"), buf);
        _tprintf(_T("  Access mask  : 0x%08X\n"), pAce->Mask);
        _tprintf(_T("  Specific mask: 0x%X\n"),   pAce->Mask&SPECIFIC_RIGHTS_ALL);
    }
}

///
/// <summary>Print out to the stdout help information.</summary>
///
VOID WINAPI
Usage()
{
    _putts(_T("Print the DACL of the named kernel objects. Supported objects:"));
    _putts(_T("  * event;"));
    _putts(_T("  * mutex;"));
    _putts(_T("  * semaphore;"));
    _putts(_T("  * shared section;"));
    _putts(_T("  * job;"));
    _putts(_T("  * waitable timer;"));
    _putts(_T("  * named pipe;"));
    _putts(_T("  * mailslot;"));
    _putts(_T("  * file.\n"));
    _putts(_T("Using:"));
    _putts(_T("   Get-DACL.exe object_name1 [object_name2] ..."));
    _putts(_T("Usage example:"));
    _putts(_T("   Get-DACL.exe C:\\Windows\\system32\\ntdll.dll"));
}

int
_tmain(int argc, TCHAR *argv[])
{
    if (1 == argc) {
        Usage();
        return (ERROR_SUCCESS);
    }
    
    for (int i = 1; i < argc; ++i) {
        _putts(_T("=========================="));
        PrintDACL(argv[i]);
        _putts(_T("=========================="));
    }
    return (GetLastError());
}
