#include "ScannerManager.h"
#include "HiddenThreadScanner.h"
#include "SystemThreadScanner.h"
#include "DriverObjectScanner.h"
#include "SsdtScanner.h"

PDRIVER_OBJECT g_drvObj;
ScannerManager* scannerManager;

HiddenThreadScanner* hiddenThreadScanner;
SystemThreadScanner* systemThreadScanner;
DriverObjectScanner* driverObjectScanner;
//SsdtScanner* ssdtScanner;

NTSTATUS InitializeScanners()
{
	scannerManager = new ScannerManager();
	// todo: may be create instances of class inside AddScanner, 
	// and args of ctors recieve from config?
	hiddenThreadScanner = new HiddenThreadScanner();
	systemThreadScanner = new SystemThreadScanner(g_drvObj);
	driverObjectScanner = new DriverObjectScanner(g_drvObj);
	//ssdtScanner = new SsdtScanner();

	NTSTATUS NtStatus = STATUS_SUCCESS;

	NtStatus = scannerManager->AddScanner(hiddenThreadScanner);
	if (!NT_SUCCESS(NtStatus))
	{
		return NtStatus;
	}

	NtStatus = scannerManager->AddScanner(systemThreadScanner);
	if (!NT_SUCCESS(NtStatus))
	{
		return NtStatus;
	}

	NtStatus = scannerManager->AddScanner(driverObjectScanner);
	if (!NT_SUCCESS(NtStatus))
	{
		return NtStatus;
	}

	//NtStatus = scannerManager->AddScanner(ssdtScanner);
	//if (!NT_SUCCESS(NtStatus))
	//{
	//	return NtStatus;
	//}

	// another scanners
}

VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	DbgPrint(PREFIX "Stopping all scanners...\n");

	UNREFERENCED_PARAMETER(DriverObject);

	if (scannerManager)
	{
		scannerManager->StopAll();
		delete scannerManager;
	}

	//UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);
	//IoDeleteSymbolicLink(&symbolicLink);
	//IoDeleteDevice(DriverObject->DeviceObject);
}

extern "C"
{
	NTSTATUS
	DriverEntry(PDRIVER_OBJECT drvObj, PUNICODE_STRING regPath)
	{
		UNREFERENCED_PARAMETER(regPath);

		g_drvObj = drvObj;
		drvObj->DriverUnload = DriverUnload;

		//UNICODE_STRING driverName;
		//RtlInitUnicodeString(&driverName, L"\\Driver\\RootkitDetector");

		NTSTATUS NtStatus = STATUS_SUCCESS;

		//NtStatus IoCreateDriver

		// todo: create device for IOCTL

		NtStatus = InitializeScanners();
		if (!NT_SUCCESS(NtStatus))
		{
			return NtStatus;
		}

		scannerManager->StartAll();

		return NtStatus;
	}
}
