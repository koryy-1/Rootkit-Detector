#pragma once

#include <ntifs.h>
#include "common.h"
#include "utils.h"

// Global Variables
PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;
PVOID ntBase;
ULONG ntSize;

BOOLEAN g_SSDTHooksDetection = TRUE;
KEVENT g_SSDTHooksDetectionFinishedEvent;

/*
	A function that scans the SSDT for hooks.
	Input: A list to store the results at.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanSSDT()
{
	if (ssdt == nullptr)
	{
		DbgPrint(PREFIX "[-] Ssdt not found\n");
		return STATUS_UNSUCCESSFUL;
	}

	ULONG CurrentSyscallRoutine = 0;

	// Scan SSDT routines whether they are in ntoskrnl range or not
	for (ULONG i = 0; i < ssdt->NumberOfServices; ++i)
	{
		DbgPrint(PREFIX "[i] ssdt->NumberOfServices %d\n", ssdt->NumberOfServices);

		CurrentSyscallRoutine = *(PULONG)((ULONG)ssdt + i * sizeof(ULONG));
		if (!(CurrentSyscallRoutine >= (ULONG)ntBase && CurrentSyscallRoutine <= (ULONG)ntBase + ntSize))
		{
			// is hooked
			DbgPrint(PREFIX "[-] Found SSDT Hook at syscall index %d\n", i);
		}
		else
		{
			// is norm
			DbgPrint(PREFIX "[-] Syscall index %d not hooked\n", i);
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Scans for SSDT hooks
 */
VOID DetectSSDTHooks(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	KeInitializeEvent(&g_SSDTHooksDetectionFinishedEvent, NotificationEvent, FALSE);

	NTSTATUS status = GetSSDTAddress();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to get SSDT address\n");
		return;
	}

	do
	{
		DbgPrint(PREFIX "Starting to look for SSDT hooks\n");
		ScanSSDT();
		SleepMs(3000);

	} while (g_SSDTHooksDetection);

	KeSetEvent(&g_SSDTHooksDetectionFinishedEvent, 0, TRUE);
	KeWaitForSingleObject(&g_SSDTHooksDetectionFinishedEvent, Executive, KernelMode, FALSE, NULL);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS GetSSDTAddress() {
	ULONG infoSize = 0;
	PVOID ssdtRelativeLocation = NULL;
	PVOID ntoskrnlBase = NULL;
	PSYSTEM_MODULE_INFORMATION info = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";

	// Getting ntoskrnl base first.
	status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &infoSize);

	while (status == STATUS_INFO_LENGTH_MISMATCH) {
		if (info)
			ExFreePoolWithTag(info, DRIVER_TAG);
		info = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, infoSize, DRIVER_TAG);

		if (!info) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		status = ZwQuerySystemInformation(SystemModuleInformation, info, infoSize, &infoSize);
	}

	if (!NT_SUCCESS(status) || !info)
		return status;

	PSYSTEM_MODULE_ENTRY modules = info->Modules;

	for (ULONG i = 0; i < info->Count; i++) {
		if (NtCreateFile >= modules[i].ImageBase && NtCreateFile < (PVOID)((PUCHAR)modules[i].ImageBase + modules[i].ImageSize)) {
			ntoskrnlBase = modules[i].ImageBase;
			ntBase = modules[i].ImageBase;
			ntSize = modules[i].ImageSize;
			break;
		}
	}

	if (!ntoskrnlBase) {
		ExFreePoolWithTag(info, DRIVER_TAG);
		return STATUS_NOT_FOUND;
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlBase;

	// Finding the SSDT address.
	status = STATUS_NOT_FOUND;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		ExFreePoolWithTag(info, DRIVER_TAG);
		return STATUS_INVALID_ADDRESS;
	}

	PFULL_IMAGE_NT_HEADERS ntHeaders = (PFULL_IMAGE_NT_HEADERS)((PUCHAR)ntoskrnlBase + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		ExFreePoolWithTag(info, DRIVER_TAG);
		return STATUS_INVALID_ADDRESS;
	}

	PIMAGE_SECTION_HEADER firstSection = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

	for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + ntHeaders->FileHeader.NumberOfSections; section++) {
		if (strcmp((const char*)section->Name, ".text") == 0) {
			ssdtRelativeLocation = FindPattern(pattern, 0xCC, sizeof(pattern) - 1, (PUCHAR)ntoskrnlBase + section->VirtualAddress, section->Misc.VirtualSize, NULL, NULL);

			if (ssdtRelativeLocation) {
				status = STATUS_SUCCESS;
				ssdt = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)ssdtRelativeLocation + *(PULONG)((PUCHAR)ssdtRelativeLocation + 3) + 7);
				break;
			}
		}
	}

	ExFreePoolWithTag(info, DRIVER_TAG);
	return status;
}
