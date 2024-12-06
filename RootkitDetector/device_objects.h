#pragma once

#include "common.h"
#include "utils.h"

BOOLEAN g_scanDriverObjects = TRUE;
KEVENT g_scanDriverObjectsFinishedEvent;
ULONG_PTR g_hashBucketLock = NULL;

NTSTATUS
ScanDriverObjects(PDRIVER_OBJECT drvObj, PULONG_PTR pHashBucketLock, POBJECT_DIRECTORY directoryObject)
{
    // Lock for the hashbucket
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusiveEx(pHashBucketLock, 0);

    for (POBJECT_DIRECTORY_ENTRY entry : directoryObject->HashBuckets)
    {
        if (!entry)
        {
            continue;
        }

        while (entry != nullptr && entry->Object)
        {
            PDRIVER_OBJECT driver = (PDRIVER_OBJECT)entry->Object;

            // Check memory of DriverStart
            if (UkGetDriverForAddress((ULONG_PTR)driver->DriverStart, drvObj) == NULL)
            {
                DbgPrint(PREFIX "[DeviceObjectScanner] -> Detected DriverObject.DriverStart pointing to unbacked or invalid region %ws @ 0x%llx\n",
                    driver->DriverName.Buffer,
                    (ULONG_PTR)driver->DriverStart
                );
            }
            if (UkGetDriverForAddress((ULONG_PTR)driver->DriverInit, drvObj) == NULL)
            {
                DbgPrint(PREFIX "[DeviceObjectScanner] -> Detected DriverEntry pointing to unbacked region %ws @ 0x%llx\n",
                    driver->DriverName.Buffer,
                    (ULONG_PTR)driver->DriverInit
                );
            }

            entry = entry->ChainLink;
        }
    }

    ExReleasePushLockExclusiveEx(pHashBucketLock, 0);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

/**
 * Iterates all driver objects to check for hints to unbacked memory.
 *
 * Original Credit: https://github.com/not-wlan/driver-hijack/blob/master/memedriver/hijack.cpp#L136
 */
VOID
UkCheckDriverObjects(IN PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    KeInitializeEvent(&g_scanDriverObjectsFinishedEvent, NotificationEvent, FALSE);

    NTSTATUS status;
    PVOID directory;
    HANDLE handle;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING directoryName = RTL_CONSTANT_STRING(L"\\Driver");

    // Get Handle to \Driver directory
    InitializeObjectAttributes(&attributes, &directoryName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);
    if (!NT_SUCCESS(status))
    {
        DbgPrint(PREFIX "Couldnt get \\Driver directory handle\n");
        return;
    }

    status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);
    if (!NT_SUCCESS(status))
    {
        ZwClose(handle);
        DbgPrint(PREFIX "Couldnt get \\Driver directory object from handle\n");
        return;
    }

    POBJECT_DIRECTORY directoryObject = (POBJECT_DIRECTORY)directory;
    g_hashBucketLock = directoryObject->Lock;

    do
    {
        DbgPrint(PREFIX "Scanning DriverObjects...\n");
        //ScanDriverObjects(drvObj, &g_hashBucketLock, directoryObject);
        UkSleepMs(5000);

    } while (g_scanDriverObjects);

    ObDereferenceObject(directory);
    ZwClose(handle);

    KeSetEvent(&g_scanDriverObjectsFinishedEvent, 0, TRUE);
    KeWaitForSingleObject(&g_scanDriverObjectsFinishedEvent, Executive, KernelMode, FALSE, NULL);

    PsTerminateSystemThread(STATUS_SUCCESS);
}