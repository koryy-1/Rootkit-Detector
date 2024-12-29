#include "Scanner.h"

Scanner::Scanner() : running(FALSE), threadHandle(nullptr) {}

Scanner::~Scanner()
{
    Stop();
}

VOID Scanner::Routine(PVOID StartContext)
{
    Scanner* instance = static_cast<Scanner*>(StartContext);
    // todo: macros fir identifier for each scanner
    DbgPrint("[%s] %s\n", instance->GetName(), "Thread started");

    instance->ExecuteScan();

    DbgPrint("[%s] %s\n", instance->GetName(), "Thread stopped");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS Scanner::Start()
{
    if (running)
        return STATUS_ALREADY_INITIALIZED;

    running = TRUE;

    return PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        nullptr,
        nullptr,
        Routine,
        this
    );
}

VOID Scanner::Stop()
{
    if (!running)
        return;

    running = FALSE;

    if (threadHandle)
    {
        ZwWaitForSingleObject(threadHandle, FALSE, nullptr);
        ZwClose(threadHandle);
        threadHandle = nullptr;
    }
}

BOOLEAN Scanner::IsRunning() const
{
    return running;
}
