#pragma once

#include "Scanner.h"
#include "types.h"

class SsdtScanner : public Scanner
{
private:
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt;
    PVOID ntBase;
    ULONG ntSize;

    NTSTATUS GetSSDTAddress();

public:
    SsdtScanner();
    virtual ~SsdtScanner();

    virtual const char* GetName() override;
    virtual NTSTATUS ExecuteScan() override;

    NTSTATUS ScanSSDT();
};

