#pragma once

#include <ntifs.h>
#include "common.h"
#include "utils.h"

// ----------------------------------------------------------------------------------------------
// Functions

NTSTATUS WriteSsdtScanResults(HANDLE Handle);
NTSTATUS InitVarsSSDT();
NTSTATUS UnloadSSDT();
NTSTATUS ScanSSDT();
VOID DetectSSDTHooks(IN PVOID StartContext);


// ----------------------------------------------------------------------------------------------
// Defines and imports

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, * PSSDT;

NTKERNELAPI PSSDT KeServiceDescriptorTable;

extern BOOLEAN g_SSDTHooksDetection;
extern KEVENT g_SSDTHooksDetectionFinishedEvent;




#define ONE_LINE_SIZE 12		//SSDT| + index(0-463) + |0\n
#define SIZE_OF_ANSI_NUMBER 4
#define SIZE_OF_NUMBER 8
#define DECIMAL 10

// Global Variables
ULONG SsdtLimit = 0;
PULONG SsdtList = NULL;

BOOLEAN g_SSDTHooksDetection = TRUE;
KEVENT g_SSDTHooksDetectionFinishedEvent;


/*
	A function that scans the SSDT for hooks.
	Input: A list to store the results at.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanSSDT()
{
	ULONG CurrentSyscallRoutine = 0;
	ULONG NtBase = GetNtoskrnlBase();
	ULONG NtSize = GetNtoskrnlSize();

	if (NtBase == 0 || NtSize == 0 || SsdtLimit == 0)
	{
		DbgPrint(PREFIX "[-] One or more invalid SSDT variables\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Scan SSDT routines whether they are in ntoskrnl range or not
	for (ULONG i = 0; i < SsdtLimit; ++i)
	{
		CurrentSyscallRoutine = *(PULONG)((ULONG)KeServiceDescriptorTable + i * sizeof(ULONG));
		if (!(CurrentSyscallRoutine >= NtBase && CurrentSyscallRoutine <= NtBase + NtSize))
		{
			// is hooked
			SsdtList[i] = TRUE;
			DbgPrint(PREFIX "[-] Found SSDT Hook at syscall index %d\n", i);
		}
		else
		{
			// is norm
			SsdtList[i] = FALSE;
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Scans for SSDT hooks
 */
VOID
DetectSSDTHooks(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	KeInitializeEvent(&g_SSDTHooksDetectionFinishedEvent, NotificationEvent, FALSE);

	NTSTATUS status = InitVarsSSDT();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to init vars for SSDT\n");
		return;
	}

	do
	{
		DbgPrint(PREFIX "Starting to look for SSDT hooks\n");
		ScanSSDT();
		UkSleepMs(3000);

	} while (g_SSDTHooksDetection);

	if (!NT_SUCCESS(UnloadSSDT()))
		DbgPrint(PREFIX "[-] Failed to unload the SSDT scanner. There might be memory leaks\n");

	KeSetEvent(&g_SSDTHooksDetectionFinishedEvent, 0, TRUE);
	KeWaitForSingleObject(&g_SSDTHooksDetectionFinishedEvent, Executive, KernelMode, FALSE, NULL);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

/*
	Init the variables required for the SSDT scan.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitVarsSSDT()
{
	if (KeServiceDescriptorTable == NULL)
		return STATUS_UNSUCCESSFUL;

	SsdtLimit = *(PULONG)((ULONG)(&KeServiceDescriptorTable) + 2 * sizeof(ULONG));
	if (SsdtLimit == 0)
		return STATUS_UNSUCCESSFUL;

	SsdtList = (PULONG)ExAllocatePoolWithTag(PagedPool, SsdtLimit * sizeof(ULONG), 'SSDT');
	if (SsdtList == NULL)
		return STATUS_UNSUCCESSFUL;
	RtlZeroMemory(SsdtList, SsdtLimit * sizeof(ULONG));

	return STATUS_SUCCESS;
}

/*
	Free all resources used by the SSDT scanner.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS UnloadSSDT()
{
	// Free the scan list
	ExFreePoolWithTag(SsdtList, 'SSDT');

	return STATUS_SUCCESS;
}

/*
	Write a buffer to an external file which will contain
	the results of the SSDT scan. The results will be in
	the following format: 'SSDT|<SYSCALL_INDEX>|<HOOKED_OR_NOT>'.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS WriteSsdtScanResults(HANDLE Handle)
{
	IO_STATUS_BLOCK IoBlock;
	UNICODE_STRING uIndex;
	PCHAR Buffer = NULL;
	ULONG BufferSize, i;
	ANSI_STRING aIndex;
	NTSTATUS Status;

	if (SsdtLimit <= 0)
	{
		DbgPrint("[-] Invalid SSDT limit value \r\n");
		return STATUS_UNSUCCESSFUL;
	}

	// Allocate pool for future actions
	BufferSize = ONE_LINE_SIZE * SsdtLimit;
	Buffer = (PCHAR)ExAllocatePool(PagedPool, BufferSize);
	if (Buffer == NULL)
	{
		DbgPrint("[-] Failed to allocate memory \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	uIndex.Buffer = (PWCH)ExAllocatePool(PagedPool, SIZE_OF_NUMBER);
	uIndex.Length = uIndex.MaximumLength = SIZE_OF_NUMBER;
	if (uIndex.Buffer == NULL)
	{
		DbgPrint("[-] Failed to allocate memory \r\n");
		goto error_1;
	}
	aIndex.Buffer = (PCHAR)ExAllocatePool(PagedPool, SIZE_OF_ANSI_NUMBER);
	aIndex.Length = aIndex.MaximumLength = SIZE_OF_ANSI_NUMBER;
	if (aIndex.Buffer == NULL)
	{
		DbgPrint("[-] Failed to allocate memory \r\n");
		goto error_2;
	}

	// Zero out allocated memory
	RtlZeroMemory(Buffer, BufferSize);
	RtlZeroMemory(uIndex.Buffer, SIZE_OF_NUMBER);
	RtlZeroMemory(aIndex.Buffer, SIZE_OF_ANSI_NUMBER);


	for (i = 0; i < SsdtLimit; ++i)
	{
		// Copy 'SSDT|' to the buffer
		Status = RtlStringCbCopyA(Buffer, BufferSize, "SSDT|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to copy a string\n");
			goto error;
		}

		// Convert the syscall index to unicode string
		Status = RtlIntegerToUnicodeString(i, DECIMAL, &uIndex);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert integer to string\n");
			goto error;
		}

		// Convert the unicode string to ansi string
		Status = RtlUnicodeStringToAnsiString(&aIndex, &uIndex, FALSE);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert UNICODE string to ASCI string\n");
			goto error;
		}

		// Concatenate the syscall index to the buffer
		Status = RtlStringCbCatA(Buffer, BufferSize, aIndex.Buffer);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string\n");
			goto error;
		}

		// Concatenate whether the syscall was hooked or not
		if (SsdtList[i] == TRUE)
			Status = RtlStringCbCatA(Buffer, BufferSize, "|1\n");
		else
			Status = RtlStringCbCatA(Buffer, BufferSize, "|0\n");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string\n");
			goto error;
		}

		// Write buffer to the external file
		Status = ZwWriteFile(
			Handle,
			NULL,
			NULL,
			NULL,
			&IoBlock,
			Buffer,
			strlen(Buffer),
			NULL,
			NULL
		);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to write to a text file\n");
			goto error;
		}
	}

	ExFreePool(uIndex.Buffer);
	ExFreePool(aIndex.Buffer);
	return STATUS_SUCCESS;

error:
	ExFreePool(aIndex.Buffer);
error_2:
	ExFreePool(uIndex.Buffer);
error_1:
	ExFreePool(Buffer);
	return STATUS_UNSUCCESSFUL;
}