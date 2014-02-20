/**
 * Filename: ntapi.h
 */
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if !defined NTSTATUS
typedef DWORD NTSTATUS;
#endif

#define STATUS_SUCCESS      0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJDIR_INFORMATION {
  UNICODE_STRING   ObjectName;
  UNICODE_STRING   ObjectTypeName;
  BYTE             Data[1];
} OBJDIR_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;        
    PVOID           SecurityQualityOfService;  
} OBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = nullptr;            \
}

typedef NTSTATUS (WINAPI *NTCREATESECTION)(
    HANDLE* SectionHandle,
    ULONG   DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG  PageAttributess,
    ULONG  SectionAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (WINAPI *NTCLOSE)(
    HANDLE SectionHandle
);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS (WINAPI *NTMAPVIEWOFSECTION)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

typedef NTSTATUS (WINAPI *NTUNMAPVIEWOFSECTION)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);
