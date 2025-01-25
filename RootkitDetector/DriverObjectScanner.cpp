#include "DriverObjectScanner.h"
#include "device_objects.h"

DriverObjectScanner::DriverObjectScanner(PDRIVER_OBJECT drvObj)
    : driverObject(drvObj), pHashBucketLock(nullptr), directoryObject(nullptr)
{
    NTSTATUS status;
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

    directoryObject = (POBJECT_DIRECTORY)directory;
    pHashBucketLock = &directoryObject->Lock;

    DbgPrint("[%s] created\n", GetName());
}

DriverObjectScanner::~DriverObjectScanner()
{
    ObDereferenceObject(directory);
    ZwClose(handle);

    DbgPrint("[%s] destroyed\n", GetName());
}

const char* DriverObjectScanner::GetName()
{
    return "Driver_Object_Scanner";
}

NTSTATUS DriverObjectScanner::ExecuteScan()
{
    DbgPrint("[%s] Executing driver object scan\n", GetName());

    while (running)
    {
        DbgPrint(PREFIX "Starting driver object scan\n");
        ScanDriverObjects(driverObject, pHashBucketLock, directoryObject);
        SleepMs(5000);
    }

    DbgPrint("[%s] Scan completed\n", GetName());
    return STATUS_SUCCESS;
}