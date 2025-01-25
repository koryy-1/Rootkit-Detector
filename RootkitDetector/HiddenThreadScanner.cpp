#include "HiddenThreadScanner.h"
#include "hiding_threads.h"

HiddenThreadScanner::HiddenThreadScanner()
{
    DbgPrint("[%s] created\n", GetName());
}

HiddenThreadScanner::~HiddenThreadScanner()
{
    DbgPrint("[%s] destroyed\n", GetName());
}

const char* HiddenThreadScanner::GetName()
{
    return "Hidden_Thread_Scanner";
}

NTSTATUS HiddenThreadScanner::ExecuteScan()
{
    DbgPrint("[%s] Executing scan for hidden threads\n", GetName());

    while (running)
    {
        DbgPrint(PREFIX "Starting to look for hidden threads\n");
        WalkSystemProcessThreads();
        SleepMs(3000);
    }

    DbgPrint("[%s] Scan completed\n", GetName());
    return STATUS_SUCCESS;
}