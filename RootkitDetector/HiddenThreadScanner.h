#pragma once

#include "Scanner.h"

class HiddenThreadScanner : public Scanner
{
public:
    HiddenThreadScanner();
    virtual ~HiddenThreadScanner();

    virtual const char* GetName() override;
    virtual NTSTATUS ExecuteScan() override;
};

