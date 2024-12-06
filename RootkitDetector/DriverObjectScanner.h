#pragma once

#include "Scanner.h"
#include "types.h"

class DriverObjectScanner : public Scanner
{
private:
    PDRIVER_OBJECT driverObject;
    PULONG_PTR pHashBucketLock;
    POBJECT_DIRECTORY directoryObject;

    PVOID directory;
    HANDLE handle;

public:
    DriverObjectScanner(PDRIVER_OBJECT drvObj);
    virtual ~DriverObjectScanner();

    virtual const char* GetName() override;
    virtual NTSTATUS ExecuteScan() override;
};

