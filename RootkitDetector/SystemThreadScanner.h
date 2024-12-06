#pragma once

#include "Scanner.h"

class SystemThreadScanner : public Scanner
{
private:
    PDRIVER_OBJECT driverObject;

public:
    SystemThreadScanner(PDRIVER_OBJECT drvObj);
    virtual ~SystemThreadScanner();

    virtual const char* GetName() override;
    virtual NTSTATUS ExecuteScan() override;
};

