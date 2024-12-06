#pragma once

#include "Scanner.h"

class ScannerManager
{
private:
    static constexpr size_t MaxScanners = 10;
    Scanner** scanners;
    size_t scannerCount;

public:
    void* operator new(size_t size) {
        return ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, size, DRIVER_TAG);
    }

    void operator delete(void* p) {
        if (p)
            ExFreePoolWithTag(p, DRIVER_TAG);
    }

    ScannerManager();
    ~ScannerManager();

    NTSTATUS AddScanner(Scanner* scanner);
    void StartAll();
    void StopAll();
    void ClearAll();
};
