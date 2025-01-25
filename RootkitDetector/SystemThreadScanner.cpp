#include "SystemThreadScanner.h"
#include "system_threads.h"

SystemThreadScanner::SystemThreadScanner(PDRIVER_OBJECT drvObj) : driverObject(drvObj)
{
    DbgPrint("[%s] created\n", GetName());
}

SystemThreadScanner::~SystemThreadScanner()
{
    DbgPrint("[%s] destroyed\n", GetName());
}

const char* SystemThreadScanner::GetName()
{
    return "System_Thread_Scanner";
}

NTSTATUS SystemThreadScanner::ExecuteScan()
{
    DbgPrint("[%s] Executing system threads scan\n", GetName());

    while (running)
    {
        DbgPrint(PREFIX "Starting system threads scan\n");
        ScanSystemThreads(driverObject);
        SleepMs(5000);
    }

    DbgPrint("[%s] Scan completed\n", GetName());
    return STATUS_SUCCESS;
}