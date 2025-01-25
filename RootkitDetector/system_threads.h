#pragma once

#include "common.h"
#include "utils.h"

BOOLEAN g_scanSystemThreads = TRUE;
KEVENT g_scanSystemThreadsFinishedEvent;

NTSTATUS
ScanSystemThreads(PDRIVER_OBJECT drvObj)
{
	// Scan system threads. TIDs are a multiple of 4 TODO: max number?
	for (auto tid = 4; tid < 0xFFFF; tid += 4)
	{
		PETHREAD ThreadObj;

		// Get ETHREAD object for TID
		if (tid == 0 || !NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(tid), &ThreadObj)))
		{
			continue;
		}

		// Ignore current thread and non system threads
		if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread())
		{
			if (ThreadObj) { ObDereferenceObject(ThreadObj); }
			continue;
		}

		// Resolve start address
		ULONG_PTR startAddress = GetThreadStartAddress(ThreadObj);
		if (startAddress != 0)
		{
			if (GetDriverForAddress(startAddress, drvObj) == NULL)
			{
				DbgPrint(PREFIX "[SystemThreadScanner] -> Detected system thread start address pointing to unbacked region: TID: %lu @ 0x%llx\n", tid, startAddress);
			}
		}

		ObDereferenceObject(ThreadObj);
	}

	return STATUS_SUCCESS;
}

/**
 * Scans all system threads for memory that is not backed by a module on disk.
 */
VOID
UkScanSystemThreads(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	KeInitializeEvent(&g_scanSystemThreadsFinishedEvent, NotificationEvent, FALSE);

	do
	{
		DbgPrint(PREFIX "Scanning running system threads...\n");
		//ScanSystemThreads(drvObj);
		SleepMs(5000);

	} while (g_scanSystemThreads);

	KeSetEvent(&g_scanSystemThreadsFinishedEvent, 0, TRUE);
	KeWaitForSingleObject(&g_scanSystemThreadsFinishedEvent, Executive, KernelMode, FALSE, NULL);
	PsTerminateSystemThread(STATUS_SUCCESS);
}