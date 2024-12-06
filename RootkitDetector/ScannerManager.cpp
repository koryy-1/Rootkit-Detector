#include "ScannerManager.h"

ScannerManager::ScannerManager()
    : scannerCount(0)
{
    // todo: may be another type
    scanners = (Scanner**)ExAllocatePool2(
        POOL_FLAG_NON_PAGED_EXECUTE,
        MaxScanners * sizeof(Scanner*),
        DRIVER_TAG
    );

    if (!scanners)
    {
        DbgPrint("[-] Failed to allocate memory for scanners\n");
    }
    
    RtlZeroMemory(scanners, MaxScanners * sizeof(Scanner*));
}

ScannerManager::~ScannerManager()
{
    StopAll();
    ClearAll();
}

NTSTATUS ScannerManager::AddScanner(Scanner* scanner)
{
    if (scannerCount >= MaxScanners)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    scanners[scannerCount++] = scanner;
    return STATUS_SUCCESS;
}

void ScannerManager::StartAll()
{
    for (size_t i = 0; i < scannerCount; ++i)
    {
        if (scanners[i])
        {
            NTSTATUS status = scanners[i]->Start();
            if (NT_SUCCESS(status))
            {
                DbgPrint("[%s] Started successfully\n", scanners[i]->GetName());
            }
            else
            {
                DbgPrint("[%s] Failed to start: 0x%x\n", scanners[i]->GetName(), status);
            }
        }
    }
}

void ScannerManager::StopAll()
{
    for (size_t i = 0; i < scannerCount; ++i)
    {
        if (scanners[i] && scanners[i]->IsRunning())
        {
            scanners[i]->Stop();
            DbgPrint("[%s] Stopped\n", scanners[i]->GetName());
        }
    }
}

void ScannerManager::ClearAll()
{
    for (size_t i = 0; i < scannerCount; ++i)
    {
        if (scanners[i])
        {
            delete scanners[i];
        }
    }

    ExFreePoolWithTag(scanners, DRIVER_TAG);
}
