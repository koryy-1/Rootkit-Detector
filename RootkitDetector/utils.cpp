#include "utils.h"

/**
 * compares two wchar strings without case sensitivity
 *
 * @param s1 first string
 * @param s2 second string
 * @return INT 0 if both string are qual
 */
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

/*
* Description:
* FindPattern is responsible for finding a pattern in memory range.
*
* Parameters:
* @pattern		  [PCUCHAR]	    -- Pattern to search for.
* @wildcard		  [UCHAR]		-- Used wildcard.
* @len			  [ULONG_PTR]	-- Pattern length.
* @base			  [const PVOID] -- Base address for searching.
* @size			  [ULONG_PTR]	-- Address range to search in.
* @foundIndex	  [PULONG]	    -- Index of the found signature.
* @relativeOffset [ULONG]		-- If wanted, relative offset to get from.
* @reversed		  [bool]		-- If want to reverse search or regular search.
*
* Returns:
* @address		  [PVOID]	    -- Pattern's address if found, else 0.
*/
PVOID
FindPattern(
	PCUCHAR pattern,
	UCHAR wildcard,
	ULONG_PTR len,
	const PVOID base,
	ULONG_PTR size,
	PULONG foundIndex,
	ULONG relativeOffset,
	bool reversed
)
{
	bool found = false;

	if (pattern == NULL || base == NULL || len == 0 || size == 0)
		return NULL;

	if (!reversed) {
		for (ULONG i = 0; i < size; i++) {
			found = true;

			for (ULONG j = 0; j < len; j++) {
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j]) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return (PUCHAR)base + i + relativeOffset;
			}
		}
	}
	else {
		for (int i = (int)size; i >= 0; i--) {
			found = true;

			for (ULONG j = 0; j < len; j++) {
				if (pattern[j] != wildcard && pattern[j] != *((PCUCHAR)base - i + j)) {
					found = false;
					break;
				}
			}

			if (found) {
				if (foundIndex)
					*foundIndex = i;
				return (PUCHAR)base - i - relativeOffset;
			}
		}
	}

	return NULL;
}
