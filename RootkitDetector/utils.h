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

/**
 * compares two wchar strings without case sensitivity
 *
 * @param s1 first string
 * @param s2 second string
 * @return INT 0 if both string are qual
 */
INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2);

PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(ULONG_PTR address, PDRIVER_OBJECT drvObj);

ULONG_PTR
UkGetThreadStartAddress(PETHREAD ThreadObj);

VOID
UkSleepMs(INT milliseconds);