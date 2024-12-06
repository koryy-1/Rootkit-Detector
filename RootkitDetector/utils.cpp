#include "utils.h"

INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
	WCHAR c1, c2;

	if (s1 == s2)
		return 0;

	if (s1 == 0)
		return -1;

	if (s2 == 0)
		return 1;

	do {
		c1 = RtlUpcaseUnicodeChar(*s1);
		c2 = RtlUpcaseUnicodeChar(*s2);
		s1++;
		s2++;
	} while ((c1 != 0) && (c1 == c2));

	return (INT)(c1 - c2);
}

PKLDR_DATA_TABLE_ENTRY
UkGetDriverForAddress(ULONG_PTR address, PDRIVER_OBJECT drvObj)
{
	if (!address)
	{
		return NULL;
	}

	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(drvObj)->DriverSection;

	for (auto i = 0; i < 512; ++i)
	{
		UINT64 startAddr = UINT64(entry->DllBase);
		UINT64 endAddr = startAddr + UINT64(entry->SizeOfImage);
		if (address >= startAddr && address < endAddr)
		{
			return (PKLDR_DATA_TABLE_ENTRY)entry;
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

ULONG_PTR
UkGetThreadStartAddress(PETHREAD ThreadObj)
{
	HANDLE hThread;
	ULONG_PTR startAddress;
	ULONG bytesReturned;

	if (ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsThreadType, KernelMode, &hThread) != 0)
	{
		return NULL;
	}

	if (ZwQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &bytesReturned) != 0)
	{
		ZwClose(hThread);
		return NULL;
	}

	if (!MmIsAddressValid((PVOID)startAddress))
	{
		ZwClose(hThread);
		return NULL;
	}

	ZwClose(hThread);
	return startAddress;
}

VOID
UkSleepMs(INT milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -1 * (LONGLONG)(milliseconds * 10000);
	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}
