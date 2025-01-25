#pragma once

#include <ntifs.h>
#include "types.h"

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C NTSTATUS ZwQueryInformationThread(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
);

EXTERN_C NTSTATUS ZwQueryDirectoryObject(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer,
    IN ULONG BufferLength,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C NTSTATUS ObReferenceObjectByName(
    IN PUNICODE_STRING ObjectPath,
    IN ULONG Attributes,
    IN PACCESS_STATE PassedAccessState,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN OUT PVOID ParseContext,
    OUT PVOID* ObjectPtr
);

INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2);

PKLDR_DATA_TABLE_ENTRY
GetDriverForAddress(ULONG_PTR address, PDRIVER_OBJECT drvObj);

ULONG_PTR
GetThreadStartAddress(PETHREAD ThreadObj);

VOID
SleepMs(INT milliseconds);

PVOID
FindPattern(
    PCUCHAR pattern,
    UCHAR wildcard,
    ULONG_PTR len,
    const PVOID base,
    ULONG_PTR size,
    PULONG foundIndex,
    ULONG relativeOffset,
    bool reversed = false
);
