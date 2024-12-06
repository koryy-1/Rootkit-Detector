#pragma once

#include <ntifs.h>
#include "common.h"

class Scanner
{
protected:
    HANDLE threadHandle;
    volatile BOOLEAN running;

    static VOID Routine(PVOID StartContext);

public:
    void* operator new(size_t size) {
        return ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, size, DRIVER_TAG);
    }

    void operator delete(void* p) {
        if (p)
            ExFreePoolWithTag(p, DRIVER_TAG);
    }

    Scanner();
    virtual ~Scanner();

    virtual const char* GetName() = 0;
    virtual NTSTATUS ExecuteScan() = 0;

    NTSTATUS Start();
    VOID Stop();
    BOOLEAN IsRunning() const;
};
