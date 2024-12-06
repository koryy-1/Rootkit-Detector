#pragma once
#include <ntdef.h>

typedef struct _WNON_PAGED_DEBUG_INFO
{
	USHORT Signature;                                                       //0x0
	USHORT Flags;                                                           //0x2
	ULONG Size;                                                             //0x4
	USHORT Machine;                                                         //0x8
	USHORT Characteristics;                                                 //0xa
	ULONG TimeDateStamp;                                                    //0xc
	ULONG CheckSum;                                                         //0x10
	ULONG SizeOfImage;                                                      //0x14
	ULONGLONG ImageBase;                                                    //0x18
} WNON_PAGED_DEBUG_INFO, * WPNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	UINT32 ExceptionTableSize;
	PVOID GpValue;
	WPNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 SignatureInfo;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	PVOID CoverageSection;
	PVOID LoadedImports;
	PVOID Spare;
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[0];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

// =============================================================
//
//typedef struct ModuleData
//{
//	PAUX_MODULE_EXTENDED_INFO Data;
//	ULONG Length;
//} ModuleData, * PModuleData;


typedef struct NodeIat
{
	PCHAR ProcessName;
	ULONG Pid;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeIat* Next;

} NodeIAT, * PNodeIAT;


typedef struct NodeKernelIat
{
	PCHAR ModuleName;
	ULONG BaseAddress;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeKernelIat* Next;

} NodeKIAT, * PNodeKIAT;


typedef struct NodeIrp
{
	PUNICODE_STRING DeviceName;
	INT64 Checksum;
	BOOLEAN IsHooked;
	struct NodeIrp* Next;

} NodeIRP, * PNodeIRP;

// =============================================================
// fot driver object scan

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length;
	UCHAR ObjectTypeFlags;
	ULONG CaseInsensitive : 1;
	ULONG UnnamedObjectsOnly : 1;
	ULONG UseDefaultObject : 1;
	ULONG SecurityRequired : 1;
	ULONG MaintainHandleCount : 1;
	ULONG MaintainTypeList : 1;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	LONG* OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	LONG* ParseProcedure;
	LONG* SecurityProcedure;
	LONG* QueryNameProcedure;
	UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
	// ERESOURCE Mutex; -> not in WinDbg probably negative offset or removed
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	EX_PUSH_LOCK TypeLock;
	ULONG Key;
	LIST_ENTRY CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	PDEVICE_MAP DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;
