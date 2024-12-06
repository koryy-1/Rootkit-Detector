#pragma once

#include <ntifs.h>
#include <intrin.h>
#include "common.h"

// ---------------------------------------------------------------------------------------------------------------------
// Structures

#pragma pack(1)
typedef struct _DESC {
	UINT16 offset00;
	UINT16 segsel;
	CHAR unused : 5;
	CHAR zeros : 3;
	CHAR type : 5;
	CHAR DPL : 2;
	CHAR P : 1;
	UINT16 offset16;
} DESC, * PDESC;
#pragma pack()


#pragma pack(1)
typedef struct _IDTR {
	UINT16 bytes;
	UINT32 addr;
} IDTR;
#pragma pack()



// ---------------------------------------------------------------------------------------------------------------------
// Functions

NTSTATUS ScanIDT();
VOID DetectIDTHooks(IN PVOID StartContext);
NTSTATUS UnloadIDT();
IDTR GetIDTAddress();
NTSTATUS InitVarsIDT();
ULONG GetISRAddress(USHORT Service);
PDESC GetDescriptorAddress(USHORT Service);
NTSTATUS WriteIdtScanResults(HANDLE Handle);

// ---------------------------------------------------------------------------------------------------------------------




#define FAILED -1
#define ONE_LINE_SIZE 12		//IDT|<index(0-2047)>|0\n
#define SIZE_OF_ANSI_NUMBER 5
#define SIZE_OF_NUMBER 10
#define DECIMAL 10

// Global Variables
PULONG IdtList = NULL;
ULONG IdtLimit = 0x100;

BOOLEAN g_IDTHooksDetection = TRUE;
KEVENT g_IDTHooksDetectionFinishedEvent;


/*
	A function that scans the IDT for hooks.
	Input: A list to store the results at.
	Output: Whether the function was successful or not.
*/
NTSTATUS ScanIDT()
{
	ULONG  IsrAddr, i;

	ULONG Base = GetNtoskrnlBase();
	ULONG Size = GetNtoskrnlSize();

	for (i = 0; i < IdtLimit; ++i)
	{
		IsrAddr = GetISRAddress(i);

		if (IsrAddr == FAILED)
			IdtList[i] = FALSE;
		else if (IsrAddr < Base || IsrAddr > Base + Size)
		{
			// is hooked
			IdtList[i] = TRUE;
			DbgPrint(PREFIX "[-] Found IDT Hook at syscall index %d\n", i);
		}
		else
			IdtList[i] = FALSE;
	}

	return STATUS_SUCCESS;
}

/**
 * Scans for IDT hooks
 */
VOID
DetectIDTHooks(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	KeInitializeEvent(&g_IDTHooksDetectionFinishedEvent, NotificationEvent, FALSE);

	NTSTATUS status = InitVarsIDT();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[-] Failed to init vars for IDT\n");
		return;
	}


	DbgPrint(PREFIX "Starting to look for IDT hooks\n");
	ScanIDT();
	DbgPrint(PREFIX "Stoping to look for IDT hooks\n");

	//do
	//{
	//	DbgPrint(PREFIX "Starting to look for IDT hooks\n");
	//	ScanIDT();
	//	UkSleepMs(3000);

	//} while (g_IDTHooksDetection);

	if (!NT_SUCCESS(UnloadIDT()))
		DbgPrint(PREFIX "[-] Failed to unload the IDT scanner. There might be memory leaks\n");

	KeSetEvent(&g_IDTHooksDetectionFinishedEvent, 0, TRUE);
	KeWaitForSingleObject(&g_IDTHooksDetectionFinishedEvent, Executive, KernelMode, FALSE, NULL);
	PsTerminateSystemThread(STATUS_SUCCESS);
}


/*
	Init the variables required for the IDT scan.
	Input: None.
	Output: Whether the function was successful or not.
*/
NTSTATUS InitVarsIDT()
{
	IdtList = (PULONG)ExAllocatePoolWithTag(PagedPool, IdtLimit * sizeof(ULONG), 'IDTL');
	if (IdtList == NULL)
		return STATUS_UNSUCCESSFUL;

	RtlZeroMemory(IdtList, IdtLimit * sizeof(ULONG));
	return STATUS_SUCCESS;
}


NTSTATUS UnloadIDT()
{
	ExFreePoolWithTag(IdtList, 'IDTL');

	return STATUS_SUCCESS;
}


ULONG GetISRAddress(USHORT Service)
{
	PDESC DescAddr;
	ULONG IsrAddr;

	DescAddr = GetDescriptorAddress(Service);
	if (DescAddr == NULL || !MmIsAddressValid(DescAddr))
	{
		return FAILED;
	}

	/* calculate address of ISR from offset00 and offset16 */
	IsrAddr = DescAddr->offset16;
	IsrAddr = IsrAddr << 16;
	IsrAddr += DescAddr->offset00;
	if (IsrAddr == NULL || !MmIsAddressValid((PVOID)IsrAddr))
	{
		return FAILED;
	}
	DbgPrint("Address of the ISR is: %x.\r\n", IsrAddr);

	return IsrAddr;
}


IDTR GetIDTAddress()
{
	IDTR IdtrAddr;

	// Вызов _sidt для записи IDT
	__sidt(&IdtrAddr);

	return IdtrAddr;
}


PDESC GetDescriptorAddress(USHORT Service)
{
	/* allocate local variables */
	IDTR IdtrAddr;
	PDESC DescAddr;

	IdtrAddr = GetIDTAddress();

	/* get address of the interrupt entry we would like to hook */
	DescAddr = (PDESC)(IdtrAddr.addr + Service * 0x8);
	DbgPrint("Address of IDT Entry is: %x.\r\n", DescAddr);

	return DescAddr;
}


NTSTATUS WriteIdtScanResults(HANDLE Handle)
{
	IO_STATUS_BLOCK IoBlock;
	UNICODE_STRING uIndex;
	PCHAR Buffer = NULL;
	ULONG BufferSize, i;
	ANSI_STRING aIndex;
	NTSTATUS Status;

	// Allocate pool for future actions
	BufferSize = ONE_LINE_SIZE * IdtLimit;
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


	for (i = 0; i < IdtLimit; ++i)
	{
		// Copy 'IDT|' to the buffer
		Status = RtlStringCbCopyA(Buffer, BufferSize, "IDT|");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to copy a string \r\n");
			goto error;
		}

		// Convert the syscall index to unicode string
		Status = RtlIntegerToUnicodeString(i, DECIMAL, &uIndex);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert integer to string \r\n");
			goto error;
		}

		// Convert the unicode string to ansi string
		Status = RtlUnicodeStringToAnsiString(&aIndex, &uIndex, FALSE);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to convert UNICODE string to ASCI string \r\n");
			goto error;
		}

		// Concatenate the syscall index to the buffer
		Status = RtlStringCbCatA(Buffer, BufferSize, aIndex.Buffer);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
			goto error;
		}

		// Concatenate whether the syscall was hooked or not
		if (IdtList[i] == TRUE)
			Status = RtlStringCbCatA(Buffer, BufferSize, "|1\n");
		else
			Status = RtlStringCbCatA(Buffer, BufferSize, "|0\n");
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("[-] Failed to concatenate a string \r\n");
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
			DbgPrint("[-] Failed to write to a text file \r\n");
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